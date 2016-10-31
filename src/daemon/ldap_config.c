#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "ldap_config.h"

/************************************
 * Static functions implementations *
 ************************************/

/**
 * \brief Find comment within config file
 * \param line Line from which comment may be found
 *
 * \todo This function may not permit '#' to exist in a password or somewhere then in comment
 */
static void skip_comments(char *line)
{
  char *comment_start = strchr(line, '#');

  if (comment_start)
    *comment_start = '\0';

  return;
}

/**
 * \brief Check if the LDAP uri given seems valid
 * \param uri LDAP uri that will be given to the LDAP library
 * \return 0 if uri seems invalid
 * \return 1 if uri seems valid
 */
static int check_ldap_uri(const char	*uri)
{
  /**
   * \todo
   * TODO: Check LDAP uri validity
   */

  syslog(LOG_WARNING,
	 "config LDAP error, uri is invalid: %s",
	 uri);
  return 0;
}

/**
 * \brief Check if the LDAP basedn given seems valid
 * \param basedn LDAP basedn that will be given to the LDAP library
 * \return 0 if basedn seems invalid
 * \return 1 if basedn seems valid
 */
static int check_ldap_basedn(const char	*basedn)
{
  /**
   * \todo
   * TODO: Check LDAP basedn validity
   */

  syslog(LOG_WARNING,
	 "config LDAP error, basedn is invalid: %s",
	 basedn);
  return 0;
}

/**
 * \brief Check if the version value from config file makes sense for LDAPv2 or LDAPv3
 * \param version Version value gotten from the config file
 * \return 0 if version is invalid
 * \return 1 if version is valid
 */
static int check_ldap_version(const short version)
{
  if ((version == 2) || (version == 3))
    return 0; /* Value is OK */

  /* Value is KO */
  syslog(LOG_WARNING,
	 "config LDAP version error, value %d is invalid",
	 version);
  return 1;
}

/**************************************
 * Exported functions implementations *
 **************************************/

char *cfg_file_find(void)
{
  /**
   * \todo
   * TODO: search for more than one place for the config file
   * It's optional but conveniant for the user.
   */

  return "/etc/usbwall.cfg";
}

struct ldap_cfg *make_ldap_cfg(const char *cfg_file)
{
  FILE *stream = fopen(cfg_file, "r");
  if (!stream)
  {
    syslog(LOG_ERR, "Configuration file not accessible : %s", cfg_file);
    return NULL;
  }

  struct ldap_cfg *config = calloc(1, sizeof (struct ldap_cfg));

  /* parsing configurations from the file */
  char *buffer = NULL;
  size_t buff_size = 0;
  while (getline(&buffer, &buff_size, stream) != -1)
  {
    skip_comments(buffer);

    /* store attributes to config */
    if (!sscanf(buffer, " uri %ms ", &config->uri)
        && !sscanf(buffer, " basedn %ms ", &config->basedn)
        && !sscanf(buffer, " binddn %ms ", &config->binddn)
        && !sscanf(buffer, " bindpw %ms ", &config->bindpw)
        && !sscanf(buffer, " version %hd ", &config->version))
      syslog(LOG_WARNING,
             "config syntax error, this line is invalid %s",
             buffer);
  }

  free(buffer);
  fclose(stream);

  /* Let's be sure that LDAP value seems OK before calling the LDAP library */
  if (check_ldap_uri(config->uri) == 0 ||
      check_ldap_basedn(config->basedn) == 0 ||
      check_ldap_version(config->version) == 0)
    {
      free(config);

      return NULL;
    }

  return config;
}

void destroy_ldap_cfg(struct ldap_cfg *cfg)
{
  free(cfg->uri);
  free(cfg->basedn);
  free(cfg->binddn);
  free(cfg->bindpw);
  free(cfg);

  return;
}
