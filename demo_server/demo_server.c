#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "error_pixeldata.h"
#include "snailload_pixeldata.h"

#define LISTEN_BACKLOG          5
#define MAX_FRAME_LENGTH        (1U << 20U)
#define MAX_REQUEST_LENGTH      8192U
#define MAX_HEADER_LENGTH       8192U
#define MAX_URI_LENGTH          128U
#define MAX_TIMESLICE_USECS     10000000UL
#define DOWNLOAD_FILENAME       "plot.bmp"
#define INDEX_HTML_PATH         "index.html"
#define BITMAP_WIDTH_PIXELS     1024UL
#define MAX_FILL                (BITMAP_WIDTH_PIXELS / 2UL)
#define MAX_USER_LIST_LENGTH    50U
#define MAX_INDEX_HTML_SIZE     (2L * 1024L * 1024L)

struct __attribute__((packed)) bmp_info_header
{
  uint32_t bitmapinfo_size;
  int32_t width_pixels;
  int32_t height_pixels;
  uint16_t planes;
  uint16_t bit_depth;
  uint32_t compression;
  uint32_t image_size;
  int32_t x_pixels_per_meter;
  int32_t y_pixels_per_meter;
  uint32_t clr_used;
  uint32_t clr_important;
};

struct __attribute__((packed)) bmp_header
{
  uint16_t magic;
  uint32_t size;
  uint32_t reserved;
  uint32_t off_bits;
  struct bmp_info_header bmp_info;
};

struct __attribute__((packed)) bmp_color_table_entry
{
  uint8_t blue;
  uint8_t green;
  uint8_t red;
  uint8_t pad;
};

struct user_data
{
  pthread_mutex_t lock;
  struct in_addr active_clients[];
};

static const struct bmp_color_table_entry color_table[] = {
  {  40U,  25U,   2U,   0U },                 //background: almost black
  { 101U,  92U,  76U,   0U },                 //no idea what this is
  { 188U, 182U, 166U,   0U },                 //shadow: gray
  { 255U, 255U, 255U,   0U }                  //plot: white
};
static const size_t num_colors = sizeof(color_table) / sizeof(*color_table);

static uint32_t max_trace_length = 1024U;
static uint64_t timeslice_nsecs = (uint64_t)50U * (uint64_t)1000U * (uint64_t)1000U;
static uint64_t max_nsecs = (BITMAP_WIDTH_PIXELS / 2ULL) * 1000ULL * 1000ULL;
static unsigned tcp_user_timeout = 15000U;
static size_t max_users = 10U;
static size_t max_users_sameip = 2U;

static struct user_data *user_data = NULL; //will be mmap'ed later for all subprocesses

static const char *index_html =
  "<!DOCTYPE html>\n"
  "<head>\n"
  "<title>Download</title>\n"
  "</head>\n"
  "<body>\n"
  "<a href=\"" DOWNLOAD_FILENAME "\">Click here to get your trace!</a>\n"
  "</body>\n"
  "</html>\n";

static inline uint64_t timespec_diff_nanoseconds(const struct timespec *a, const struct timespec *b)
{
  assert(a->tv_sec > b->tv_sec || (a->tv_sec == b->tv_sec && a->tv_nsec >= b->tv_nsec));
  return (a->tv_sec - b->tv_sec) * 1000000000ULL + (a->tv_nsec - b->tv_nsec);
}

static void format_timestamp(char *buf, size_t bufsz, const struct timespec *ts)
{
  assert(bufsz >= 30);

  struct tm tm;
  if(localtime_r(&ts->tv_sec, &tm) == NULL)
  {
    perror("localtime_r");
    exit(EXIT_FAILURE);
  }

  if(strftime(buf, 20U, "%Y-%m-%d %H:%M:%S", &tm) != 19U)
    abort();

  buf[19U] = '.';

  if(snprintf(buf+20U, 10U, "%09li", ts->tv_nsec) != 9U)
    abort();
}

static inline uint32_t get_pixels_per_byte(uint16_t bit_depth)
{
  assert(bit_depth == 1U || bit_depth == 4U || bit_depth == 8U);
  return 8U / bit_depth;
}

static inline uint32_t get_row_size(uint32_t width, uint16_t bit_depth)
{
  assert(bit_depth == 1U || bit_depth == 4U || bit_depth == 8U);
  return ((bit_depth * width + 31U) / 32U) * 4U;
}

static inline uint32_t get_pixeldata_size(uint32_t width, uint32_t height, uint16_t bit_depth)
{
  return get_row_size(width, bit_depth) * height;
}

static inline uint32_t get_bmp_size(uint32_t width, uint32_t height, uint16_t bit_depth, uint32_t colors)
{
  return (uint32_t)(sizeof(struct bmp_header) + colors * sizeof(struct bmp_color_table_entry) + get_pixeldata_size(width, height, bit_depth));
}

static void bmp_header_init(struct bmp_header *h, uint32_t width, uint32_t height, uint32_t bit_depth, uint32_t colors)
{
  assert(bit_depth == 1U || bit_depth == 4U || bit_depth == 8U);    //only indexed format is supported
  assert(!(bit_depth == 1U && colors > 0U));                        //no color table for black/white

  assert(width <= INT32_MAX);
  assert(height <= INT32_MAX);

  h->magic = 0x4d42U;
  h->size = get_bmp_size(width, height, bit_depth, colors);
  h->reserved = 0U;
  h->off_bits = (uint32_t)(sizeof(*h) + colors * sizeof(struct bmp_color_table_entry));

  h->bmp_info.bitmapinfo_size = (uint32_t)sizeof(h->bmp_info);
  h->bmp_info.width_pixels = width;
  h->bmp_info.height_pixels = -height;  //negative: data is top to bottom!
  h->bmp_info.planes = 1U;
  h->bmp_info.bit_depth = bit_depth;
  h->bmp_info.compression = 0U;         //no compression
  h->bmp_info.image_size = get_pixeldata_size(width, height, bit_depth);
  h->bmp_info.x_pixels_per_meter = 0;   //unspecified
  h->bmp_info.y_pixels_per_meter = 0;   //unspecified
  h->bmp_info.clr_used = colors;
  h->bmp_info.clr_important = colors;
}

static int ignore_sigchld(void)
{
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_NOCLDWAIT;    //might as well be 0, as explicitly setting SIG_IGN for SIGCHLD already prevents zombies
  return sigaction(SIGCHLD, &act, NULL);
}

static int try_load_index_html(void)
{
  const int fd = open(INDEX_HTML_PATH, O_RDONLY);
  if(fd == -1)
  {
    perror("Failed to open " INDEX_HTML_PATH ", falling back to builtin index page");
    return -1;
  }

  struct stat buf;
  if(fstat(fd, &buf) == -1 || buf.st_size <= 0)
  {
    perror("Failed to get file size of " INDEX_HTML_PATH ", falling back to builtin index page");
    close(fd);
    return -1;
  }

  if(buf.st_size > MAX_INDEX_HTML_SIZE)
  {
    fprintf(stderr, INDEX_HTML_PATH " is too large (%ji Bytes), falling back to builtin index page\n", (intmax_t)buf.st_size);
    close(fd);
    return -1;
  }

  void *mapping = mmap(NULL, (size_t)buf.st_size, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
  if(mapping == MAP_FAILED)
  {
    perror("Failed to mmap " INDEX_HTML_PATH ", falling back to builtin index page");
    close(fd);
    return -1;
  }

  index_html = mapping;
  close(fd);
  return 0;
}

static int user_data_init(void)
{
  void *mapping = mmap(NULL, sizeof(struct user_data) + sizeof(*user_data->active_clients) * max_users, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, (off_t)0);
  if(mapping == MAP_FAILED)
    return -1;

  user_data = (struct user_data *)mapping;

  pthread_mutexattr_t attr;
  if((errno = pthread_mutexattr_init(&attr)) != 0)
    goto err_unmap;
  if((errno = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) != 0)
    goto err_attr_destroy;
  if((errno = pthread_mutex_init(&user_data->lock, &attr)) != 0)
    goto err_attr_destroy;

  pthread_mutexattr_destroy(&attr);
  return 0;

err_attr_destroy:
  pthread_mutexattr_destroy(&attr);
err_unmap:
  munmap(mapping, sizeof(struct user_data) + sizeof(*user_data->active_clients) * max_users);
  return -1;
}

static struct in_addr *user_data_add(const struct in_addr *ip)
{
  struct in_addr *entry = NULL;
  size_t num_sameip = 0U;

  pthread_mutex_lock(&user_data->lock);

  for(size_t i=0; i<max_users; ++i)
  {
    if(user_data->active_clients[i].s_addr == 0U)
    {
      if(entry == NULL)         //remember first empty entry
        entry = &user_data->active_clients[i];

      continue;
    }

    if(user_data->active_clients[i].s_addr == ip->s_addr)    //count entries with same IP
      ++num_sameip;
  }

  if(num_sameip >= max_users_sameip)                  //limit for same IP exceeded -> does not get an entry
  {
    errno = EBUSY;
    entry = NULL;
  }
  else if(entry != NULL)                              //otherwise, add entry to the list, if we found a free entry
    *entry = *ip;

  pthread_mutex_unlock(&user_data->lock);

  return entry;
}

static void user_data_remove(struct in_addr *ip)
{
  pthread_mutex_lock(&user_data->lock);
  ip->s_addr = 0U;
  pthread_mutex_unlock(&user_data->lock);
}

static int ignore_sigpipe(void)
{
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  return sigaction(SIGPIPE, &act, NULL);
}

static int create_passive_socket(uint16_t port)
{
  const int sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock == -1)
    return -1;

  const struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = htonl(INADDR_ANY)
  };

  //disable Nagle algorithm and send out packets immediately
  const int on = 1;
  if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1)
    goto err_close;

  //set SO_REUSEADDR, as testing is annoying otherwise
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
    goto err_close;

  //set TCP user timeout
  if(setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &tcp_user_timeout, sizeof(tcp_user_timeout)) == -1)
    goto err_close;

  if(bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
    goto err_close;

  if(listen(sock, LISTEN_BACKLOG) == -1)
    goto err_close;

  return sock;

err_close:
  close(sock);
  return -1;
}

static ssize_t receive_request(int fd, char *buf, size_t bufsz)
{
  assert(bufsz > 0U);
  assert(bufsz <= SSIZE_MAX);

  memset(buf, 0, bufsz);

  size_t bufpos = 0U;
  while(bufpos < bufsz-1U)
  {
    const ssize_t bytes_read = read(fd, buf+bufpos, bufsz-bufpos-1U);
    if(bytes_read == -1)
      return -1;

    if(bytes_read == 0)
    {
      errno = ENOMSG;
      return -1;
    }

    bufpos += bytes_read;

    if(memchr(buf, '\0', bufpos) != NULL)
    {
      errno = EBADMSG;
      return -1;
    }

    char *endpos = strstr(buf, "\r\n\r\n");
    if(endpos != NULL)
    {
      if(endpos + 4U != buf+bufpos)
        fprintf(stderr, "Potential second request sent by client, only processing the first one.\n");

      *(endpos+4U) = '\0';
      return bufpos;
    }
  }

  errno = EBADMSG;
  return -1;
}

static int check_request(const char *request, char *uri, size_t urisz)
{
  assert(urisz > 0U);

  //first line is the request line, consisting of the method token, the URI and the protocol version
  const char *lineend = strstr(request, "\r\n");
  const size_t linelen = lineend - request;
  if(linelen < 4U || memcmp(request, "GET ", 4U) != 0)
  {
    errno = EBADMSG;
    return -1;
  }

  //everything until a space is the URI
  size_t uripos = 0U;
  const char *reqcursor = request + 4U;
  while(*reqcursor != ' ')
  {
    if(reqcursor >= lineend || uripos >= urisz-1U)
    {
      //no space found before going out of bounds -> bad message
      errno = EBADMSG;
      return -1;
    }
    uri[uripos] = *reqcursor;
    ++uripos;
    ++reqcursor;
  }

  uri[uripos] = '\0';

  ++reqcursor;    //move from space to first character of protocol

  if(lineend - reqcursor < 8U)
  {
    //not enough bytes left to contain "HTTP/1.x" -> bad message
    errno = EBADMSG;
    return -1;
  }

  if(memcmp(reqcursor, "HTTP/1.0", 8U) != 0 && memcmp(reqcursor, "HTTP/1.1", 8U) != 0)
  {
    //unsupported protocol
    errno = EBADMSG;
    return -1;
  }

  return 0;
}

static int send_all(int client_sock, const void *data, size_t data_size)
{
  assert(data_size < SSIZE_MAX);
  const char *p = (const char *)data;

  size_t datapos = 0U;
  while(datapos < data_size)
  {
    const ssize_t bytes_sent = write(client_sock, p+datapos, data_size-datapos);
    if(bytes_sent == -1)
      return -1;

    datapos += bytes_sent;
  }

  return 0;
}

static int send_simple(int client_sock, const char *content_type, const void *data, size_t data_size)
{
  char header[MAX_HEADER_LENGTH+1U];
  const size_t written = snprintf(header, sizeof(header),
      "HTTP/1.1 200 OK\r\n"
      "Server: SnailLoadPlotgen\r\n"
      "Content-Length: %zu\r\n"
      "Content-Language: en\r\n"
      "Connection: close\r\n"
      "Content-Type: %s\r\n"
      "\r\n",
      data_size, content_type
  );
  assert(written < sizeof(header));

  if(send_all(client_sock, header, written) == -1)
    return -1;

  return send_all(client_sock, data, data_size);
}

static int send_html(int client_sock, const char *htmlstr)
{
  return send_simple(client_sock, "text/html", htmlstr, strlen(htmlstr));
}

static int send_not_found(int client_sock)
{
  static const char body[] = "<html><head><title>Not found</title></head><body>The file was not found!</body></html>";

  char header[MAX_HEADER_LENGTH+1U];
  const size_t written = snprintf(header, sizeof(header),
      "HTTP/1.1 404 File not found\r\n"
      "Server: SnailLoadPlotgen\r\n"
      "Content-Length: %zu\r\n"
      "Content-Language: en\r\n"
      "Connection: close\r\n"
      "Content-Type: text/html\r\n"
      "\r\n",
      sizeof(body)-1U
  );
  assert(written < sizeof(header));

  if(send_all(client_sock, header, written) == -1)
    return -1;

  return send_all(client_sock, body, sizeof(body)-1U);
}

static int send_index(int client_sock)
{
  return send_html(client_sock, index_html);
}

static int wait_for_ack(int client_sock)
{
  struct pollfd fds =
  {
    .fd = client_sock,
    .events = POLLERR | POLLHUP,
    .revents = 0
  };

  for(;;)
  {
    //abort if connection is closed
    const int poll_res = poll(&fds, 1, 0);
    if(poll_res == -1 || poll_res == 1)
      return -1;

    //check if send buffer is empty now
    int unsent;     //is actually an int, yes, see net/ipv4/tcp.c in the linux source code
    if(ioctl(client_sock, SIOCOUTQ, &unsent) != 0)
      return -1;
    if(unsent == 0)
      return 0;
  }
}

static void set_pixel_color(uint8_t *row, size_t row_size, uint16_t bit_depth, uint32_t x, uint8_t color)
{
  assert(bit_depth == 1U || bit_depth == 4U || bit_depth == 8U);

  uint8_t bit_mask;
  switch(bit_depth)
  {
    case 1U:
      bit_mask = 0x80U;
      break;

    case 4U:
      bit_mask = 0xf0U;
      break;

    case 8U:
      bit_mask = 0xffU;
      break;
  }

  const size_t byte = x / get_pixels_per_byte(bit_depth);
  assert(byte < row_size);
  const size_t pixel_in_byte = x % get_pixels_per_byte(bit_depth);
  const size_t mask = bit_mask >> (pixel_in_byte * bit_depth);

  row[byte] &= ~mask;                     //unset old color
  row[byte] |= (color << (bit_depth - pixel_in_byte * bit_depth));  //set new color
}

static void paint_row(uint8_t *row, size_t row_size, uint16_t bit_depth, uint32_t max_x, uint64_t max_latency, uint64_t latency, uint64_t index)
{
  assert(get_row_size(max_x, bit_depth) <= row_size);

  if(latency > max_latency)
    latency = max_latency;

  const double fraction_filled = (double)latency / (double)max_latency;
  uint32_t pixels_filled = (uint32_t)(max_x * fraction_filled);
  if(pixels_filled > max_x)
    pixels_filled = max_x;

  //set everything to background color...
  memset(row, 0, row_size);
  //...except for the start of the row, for the given length
  uint32_t i=0U;
  for(; i<pixels_filled; ++i)
    set_pixel_color(row, row_size, bit_depth, i, 3U);
  if(index < 1024)      //paint background, if we still have data for it
    for(; i<1024; ++i)
      set_pixel_color(row, row_size, bit_depth, i, snailload_pixeldata[index * 1024 + i]);
}

static int send_full(int client_sock)
{
  const uint32_t row_size = get_row_size(BITMAP_WIDTH_PIXELS, 4U);
  uint8_t *row = calloc(row_size, sizeof(uint8_t));
  if(row == NULL)
    return -1;

  //send HTTP header
  static char header[] =
      "HTTP/1.1 200 OK\r\n"
      "Server: SnailLoadPlotgen\r\n"
      "Cache-Control: no-cache\r\n"
      "Content-Language: en\r\n"
      "Connection: close\r\n"
      "Content-Type: image/bmp\r\n"
      "\r\n";
  if(send_all(client_sock, header, sizeof(header)-1U) == -1)
    goto err_free;

  //send BMP header
  struct bmp_header bmp_header;
  bmp_header_init(&bmp_header, BITMAP_WIDTH_PIXELS, max_trace_length, 4U, num_colors);
  if(send_all(client_sock, &bmp_header, sizeof(bmp_header)) == -1)
    goto err_free;

  //send color table
  if(send_all(client_sock, color_table, sizeof(color_table)) == -1)
    goto err_free;

  //send error image, line by line
  for(size_t i=0U; i<max_trace_length; ++i)
  {
    memset(row, 0, row_size);
    for(uint32_t j=0U; j<BITMAP_WIDTH_PIXELS; ++j)
      set_pixel_color(row, row_size, 4U, j, error_pixeldata[i * 1024U + j]);

    const ssize_t bytes_sent = send(client_sock, row, row_size, 0);
    if(bytes_sent == -1)
    {
      if(errno != EPIPE && errno != ECONNRESET && errno != ETIMEDOUT)     //error
        goto err_free;

      break;                                                              //client has closed the connection or sneaked away -> not an actual error
    }
  }

  free(row);
  return 0;

err_free:
  free(row);
  return -1;
}

static int send_trace(int client_sock, const char *client_addr)
{
  const uint32_t row_size = get_row_size(BITMAP_WIDTH_PIXELS, 4U);
  uint8_t *row = calloc(row_size, sizeof(uint8_t));
  if(row == NULL)
    return -1;

  struct timespec start_time;
  if(clock_gettime(CLOCK_REALTIME, &start_time) == -1)
    goto err_free;

  char ts_buffer[30];
  format_timestamp(ts_buffer, sizeof(ts_buffer), &start_time);
  fprintf(stderr, "Client %s started download at %s\n", client_addr, ts_buffer);

  //send HTTP header
  static char header[] =
      "HTTP/1.1 200 OK\r\n"
      "Server: SnailLoadPlotgen\r\n"
      "Cache-Control: no-cache\r\n"
      "Content-Language: en\r\n"
      "Connection: close\r\n"
      "Content-Type: image/bmp\r\n"
      "\r\n";
  if(send_all(client_sock, header, sizeof(header)-1U) == -1)
    goto err_free;

  //send BMP header
  struct bmp_header bmp_header;
  bmp_header_init(&bmp_header, BITMAP_WIDTH_PIXELS, max_trace_length, 4U, num_colors);
  if(send_all(client_sock, &bmp_header, sizeof(bmp_header)) == -1)
    goto err_free;

  //send color table
  if(send_all(client_sock, color_table, sizeof(color_table)) == -1)
    goto err_free;

  //generate trace and send it, row by row
  uint64_t previous_timeslice_number = SIZE_MAX;
  uint64_t previous_latency = 0UL;
  uint64_t current_row = 0U;
  for(;;)
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    const uint64_t nsecs_since_start = timespec_diff_nanoseconds(&now, &start_time);
    const uint64_t timeslice_number = nsecs_since_start / timeslice_nsecs;

    if(current_row >= max_trace_length)
    {
      fprintf(stderr, "Trace for %s finished.\n", client_addr);
      break;
    }

    if(previous_timeslice_number == SIZE_MAX || timeslice_number > previous_timeslice_number)
    {
      //new timeslice, record this as the previous timeslice number for subsequent iterations
      previous_timeslice_number = timeslice_number;

      //paint previous latency into the row
      paint_row(row, row_size, 4U, MAX_FILL, max_nsecs, previous_latency, current_row);

      //send
      const ssize_t bytes_sent = send(client_sock, row, row_size, 0);
      if(bytes_sent == -1)
      {
        if(errno != EPIPE && errno != ECONNRESET && errno != ETIMEDOUT)     //error
          goto err_free;

        break;                                                              //client has closed the connection or sneaked away -> not an actual error, save trace
      }
      if(wait_for_ack(client_sock) == -1)
        break;

      struct timespec ack_received;
      clock_gettime(CLOCK_REALTIME, &ack_received);
      const uint64_t latency = timespec_diff_nanoseconds(&ack_received, &now);

      previous_latency = latency;
      ++current_row;
    }
  }

  return 0;

err_free:
  free(row);
  return -1;
}

static int handle_connection(int client_sock, const struct in_addr *client_addr, const char *client_addr_str)
{
  char request[MAX_REQUEST_LENGTH];
  ssize_t request_length = receive_request(client_sock, request, sizeof(request));
  if(request_length == -1)
  {
    fprintf(stderr, "Error receiving request from %s: %s\n", client_addr_str, strerror(errno));
    return -1;
  }

  char uri[MAX_URI_LENGTH];
  if(check_request(request, uri, sizeof(uri)) == -1)
  {
    fprintf(stderr, "Invalid request from %s\n", client_addr_str);
    return -1;
  }

  fprintf(stderr, "%s requested: %s\n", client_addr_str, uri);

  if(strcmp(uri, "/") == 0)
    return send_index(client_sock);

  if(strcmp(uri, "/" DOWNLOAD_FILENAME) == 0)
  {
    struct in_addr *entry = user_data_add(client_addr);
    if(entry == NULL)
    {
      fprintf(stderr, "Rejecting %s due to connection limit\n", client_addr_str);
      return send_full(client_sock);
    }

    const int status = send_trace(client_sock, client_addr_str);

    user_data_remove(entry);
    return status;
  }

  return send_not_found(client_sock);
}

static int handle_connections(int passive_sock)
{
  for(;;)
  {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    const int client_sock = accept(passive_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if(client_sock == -1)
    {
      if(errno == ECONNABORTED)
        continue;

      perror("accept");
      return -1;
    }

    assert(client_addr_len <= sizeof(client_addr));

    char client_addr_str[INET_ADDRSTRLEN];
    if(inet_ntop(AF_INET, &client_addr.sin_addr, client_addr_str, client_addr_len) == NULL)
      strcpy(client_addr_str, "???");

    const pid_t pid = fork();
    if(pid == -1)
    {
      fprintf(stderr, "Error forking subprocess for client %s, dropping it: %s\n", client_addr_str, strerror(errno));
      close(client_sock);
      continue;
    }
    else if(pid == 0)     //child
    {
      close(passive_sock);

      if(ignore_sigpipe() == -1)
      {
        perror("ignore_sigpipe");
        close(client_sock);
        exit(EXIT_FAILURE);
      }

      if(handle_connection(client_sock, &client_addr.sin_addr, client_addr_str) == -1)
      {
        fprintf(stderr, "Error handling connection for client %s, dropping it: %s\n", client_addr_str, strerror(errno));
        close(client_sock);
        exit(EXIT_FAILURE);
      }
      close(client_sock);
      fprintf(stderr, "Connection closed for client %s.\n", client_addr_str);
      exit(EXIT_SUCCESS);
    }
    else                //parent
    {
      fprintf(stderr, "Started subprocess with PID = %ji for client %s.\n", (intmax_t)pid, client_addr_str);
      close(client_sock);
    }
  }
}

static uintmax_t umax_from_cmdline(const char *name, const char *val, uintmax_t min, uintmax_t max)
{
  char *endptr;
  const uintmax_t conv = strtoumax(val, &endptr, 0);
  if(endptr == val || *endptr != '\0' || conv < min || conv > max)
  {
    fprintf(stderr, "%s has to be an unsigned integer between %ju and %ju.\n", name, min, max);
    exit(EXIT_FAILURE);
  }

  return conv;
}

static __attribute__((noreturn)) void usage(const char *argv0)
{
  fprintf(stderr, "Usage: %s [OPTIONS]\n", argv0);
  fprintf(stderr, "  -l MAX_TRACE_LEN       Change the maximum trace length to the given number of samples (default: 1024)\n");
  fprintf(stderr, "  -m MAX_NSECS           Change the maximum for the trace axis (default: 512000000)\n");
  fprintf(stderr, "  -p PORT                Listen on the specified port (default: 10443)\n");
  fprintf(stderr, "  -t TIMESLICE_USECS     Change the timeslice length (default: 50000)\n");
  fprintf(stderr, "  -T TCP_USER_TIMEOUT_MS Set the TCP user timeout in milliseconds (default: 15000)\n");
  fprintf(stderr, "  -u MAX_USERS           Maximum number of users generating traces in parallel (default: 10)\n");
  fprintf(stderr, "  -U MAX_USERS_SAMEIP    Maximum number of users with the same IP address generating traces in parallel (default: 2)\n");
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
  uint16_t port = 10443;

  tzset();

  int opt;
  while((opt = getopt(argc, argv, ":l:m:p:t:T:u:U:")) != -1)
  {
    switch(opt)
    {
      case 'l':
        max_trace_length = (uint32_t)umax_from_cmdline("MAX_TRACE_LEN", optarg, 1U, 10000U);
        break;

      case 'm':
        max_nsecs = (uint64_t)umax_from_cmdline("MAX_NSECS", optarg, 2U, 5000ULL * 1000ULL * 1000ULL);
        break;

      case 'p':
        port = (uint16_t)umax_from_cmdline("PORT", optarg, 1U, 0xffffU);
        break;

      case 't':
        timeslice_nsecs = (uint64_t)1000U * (uint64_t)umax_from_cmdline("TIMESLICE_USECS", optarg, 1U, MAX_TIMESLICE_USECS);
        break;

      case 'T':
        tcp_user_timeout = (unsigned)umax_from_cmdline("TCP_USER_TIMEOUT", optarg, 0U, 10000U);
        break;

      case 'u':
        max_users = (size_t)umax_from_cmdline("MAX_USERS", optarg, 1U, MAX_USER_LIST_LENGTH);
        break;

      case 'U':
        max_users_sameip = (size_t)umax_from_cmdline("MAX_USERS_SAMEIP", optarg, 1U, MAX_USER_LIST_LENGTH);
        break;

      default:
        usage(argv[0]);
        __builtin_unreachable();
    }
  }

  if(optind != argc)
    usage(argv[0]);

  if(user_data_init() == -1)
  {
    perror("ignore_sigchld");
    return EXIT_FAILURE;
  }

  if(ignore_sigchld() == -1)
  {
    perror("ignore_sigchld");
    return EXIT_FAILURE;
  }

  const int passive_socket = create_passive_socket(port);
  if(passive_socket == -1)
  {
    perror("create_passive_socket");
    return EXIT_FAILURE;
  }

  try_load_index_html();

  fprintf(stderr, "Will generate traces for at most %f seconds.\n", (double)max_trace_length * ((double)timeslice_nsecs / 1.0e9));
  fprintf(stderr, "Trace image size will be %" PRIu32 " bytes.\n", get_bmp_size(BITMAP_WIDTH_PIXELS, max_trace_length, 4U, num_colors));
  fprintf(stderr, "Each row will have %" PRIu32 " bytes.\n", get_row_size(BITMAP_WIDTH_PIXELS, 4U));

  return handle_connections(passive_socket) == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
