#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <libgen.h>

#include "server.h"
#include "misc/error_handler.h"
#include "misc/debug.h"


/**
 * \brief Create server socket
 *
 *
 */

int32_t serv_socket(int32_t *sock_fd)
{
  *sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (*sock_fd < 0)
  {
    syslog(LOG_ERR, "%s, %d: Cannot create socket for server",
           __FILENAME__, __LINE__);
    return DEVIDD_ERR_OTHER;
  }

  return DEVIDD_SUCCESS;
}


int32_t serv_bind(int32_t *sock_fd, struct sockaddr_in *serv_addr)
{
  int32_t b = 0; /* Return value for bind() */

  /* Declare struct serv_addr which will contain the sock_fd address */
  memset(serv_addr, 0, sizeof(*serv_addr)); /* FIXME: BSD: bzero */
  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(SERV_PORT);
  serv_addr->sin_addr.s_addr = htonl(INADDR_ANY);

  /* Bind sock_fd with this address */
  b = bind(*sock_fd, (struct sockaddr*) serv_addr, sizeof(*serv_addr));

  if (b < 0)
  {
    printf("[serv_bind]:%s\n", strerror(errno));
    syslog(LOG_ERR, "%s, %d: Cannot bind server socket",
           __FILENAME__, __LINE__);
    return DEVIDD_ERR_OTHER;
  }

  return DEVIDD_SUCCESS;
}

int32_t serv_recv(int32_t *sock_fd, char **buf,
                  struct sockaddr_in *serv_addr)
{
  ssize_t r = 0; /* Return value for recvfrom() */
  uint32_t size_serv = sizeof (serv_addr); /* Size of serv_addr */

  /* Receive data from client
     - blocks until datagram received from the client */

  r = recvfrom(*sock_fd, *buf, BUF_LEN, 0,
      (struct sockaddr *) serv_addr,
      &size_serv);

  /* Handle recvfrom() failure */
  if (r < 0)
  {
    syslog(LOG_ERR, "%s, %d: Cannot receive from client to server",
           __FILENAME__, __LINE__);
    return DEVIDD_ERR_OTHER;
  }

  /* buf[r] = '\0'; */

  return DEVIDD_SUCCESS;

}

int32_t serv_send(int32_t *sock_fd, char **buf,
                  struct sockaddr_in *serv_addr)
{
  ssize_t s = 0; /* Return value for sendto() */
  uint32_t size_serv = sizeof (*serv_addr);
  /* Send data to the client */
  s = sendto(*sock_fd, *buf, BUF_LEN, 0,
      (struct sockaddr *) serv_addr,
      size_serv);

  /* Handle sendto() failure */
  if (s < 0)
  {
    printf("[serv_send]:%s\n", strerror(errno));
    syslog(LOG_ERR, "%s, %d: Cannot send from server to client",
           __FILENAME__, __LINE__);
    return DEVIDD_ERR_OTHER;
  }

  return DEVIDD_SUCCESS;
}


void *serv_core(void *arg __attribute__((unused)))
{
  int32_t sock_fd = 0; /* Server socket */
  uint32_t error = 0; /* Error handler */
  char *buf = NULL; /* Buffer received from the client */
  struct sockaddr_in serv_addr; /* Server address */

  /* Create socket for server and bind it */
  if ((serv_socket(&sock_fd) != DEVIDD_SUCCESS)
      || (serv_bind(&sock_fd, &serv_addr) != DEVIDD_SUCCESS))
  {
    /* return DEVIDD_ERR_OTHER; */
    return NULL;
  }

  buf = calloc(1, BUF_LEN);
  if (!buf)
  {
    syslog(LOG_ERR, "%s, %d: Memory allocation error",
           __FILENAME__, __LINE__);

    /* return DEVIDD_ERR_OTHER_MEM; */
    return NULL;
  }

  while (!error)
  {
    /* syslog(LOG_ERR, "[SERVER] Buffer before reception: %s", buf);*/
    if (serv_recv(&sock_fd, &buf, &serv_addr) != DEVIDD_SUCCESS)
    {
      /* return DEVIDD_ERR_OTHER; */
      error = DEVIDD_ERR_OTHER;
      break;
    }

    /* FIXME: treatment */
    printf("Client: %s\n", buf);
    buf = strdup("Because.");

    //syslog(LOG_ERR, "[SERVER] Buffer sent to client: %s", buf);

    if (serv_send(&sock_fd, &buf, &serv_addr) != DEVIDD_SUCCESS)
    {
      /* return DEVIDD_ERR_OTHER; */
      error = DEVIDD_ERR_OTHER;
      break;
    }
  }

  free(buf);

  if (close(sock_fd) < 0)
  {
    syslog(LOG_ERR, "%s, %d: Cannot close server socket",
           __FILENAME__, __LINE__);
    /* return DEVIDD_ERR_OTHER; */
      error = DEVIDD_ERR_OTHER;
    return NULL;
  }

  /* return DEVIDD_SUCCESS; */
  return NULL;
}

