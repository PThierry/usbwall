#include <stdio.h>
#include <stdlib.h>

#include "devusb.h"
#include "devuser.h"
#include "ldap_config.h"
#include "socket.h"

int main(void)
{
  struct ldap_cfg *cfg = make_ldap_cfg(cfg_file_find());
  int netlink_fd = -1;

  if (!cfg)
    return 1; // no configs found

  if (init_devusb())
    return 1; // devusb initialization error

  if ((netlink_fd = init_socket()) == -1)
    return 1; // netlink initialization error

  char *username = NULL;
  while ((username = wait_for_logging(netlink_fd)))
  {
    struct devusb **device_list = devices_get();
    char **devids = devids_get(username, cfg);

    /**
     * \todo
     * TODO: update devices_list depending of devids.
     * Only authorized devices should be kept
     */

    update_devices(device_list);

    free_devids(devids);
    free_devices(device_list);
    free(username);

    break; // for debug purpose
  }
  close_devusb();
  destroy_ldap_cfg(cfg);

  return 0;
}
