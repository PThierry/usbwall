#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>


#include "format_validity.h"
#include "../misc/error_handler.h"

/* Serial format
 * - min: 12 characters
 * - max: 126 characters
 * - type: 0-9, A-F
 */ 

int32_t check_serial_format(char *serial)
{
  uint32_t i = 0;
  uint32_t len = 0; 

  /* Check lenght validity */
  len = strlen(serial);
  if ((len < 12) || (len > 126))
  {
    return DEVIDD_ERR_OTHER;
  }

  for (i = 0; i < len; i++)
  {
    /* A character is valid if and only if its format is hexadecimal
       and if it is not a lowercase */
    if (!isxdigit(serial[i]) || islower(serial[i]))
    {
      return DEVIDD_ERR_OTHER;
    } 
  }
  return DEVIDD_SUCCESS;
}

/* Vendor/product format:
 * - fixed size: 4
 * - type: 0-9, A-F
 */

int32_t check_vendor_product_format(char *str)
{
  int32_t i = 0;

  if (strlen(str) != LEN_VENDOR_PRODUCT)
  {
    return DEVIDD_ERR_OTHER;
  }

  for (i = 0; i < LEN_VENDOR_PRODUCT; i++)
  {
    /* A character is valid if and only if its format is hexadecimal
       and if it is not a lowercase */
    if (!isxdigit(str[i]) || islower(str[i]))
    {
      return DEVIDD_ERR_OTHER;
    } 
  }
  return DEVIDD_SUCCESS;
}

/* Bcd_device format:
 * - fixed size: 16
 * - type: 0-1
 */
 int32_t check_bcd_format(char *bcd)
 { 
  int32_t i = 0;

  if (strlen(bcd) != LEN_BCD)
  {
    return DEVIDD_ERR_OTHER;
  }

  for (i = 0; i < LEN_BCD; i++)
  {
    /* A character is valid if and only if its format is hexadecimal
       and if it is not a lowercase */
    if ((bcd[i] != '0') && (bcd[i] != '1'))
    {
      return DEVIDD_ERR_OTHER;
    } 
  }
  return DEVIDD_SUCCESS;
 }


int32_t check_machine_format(char *machine)
{
  if (machine != LEN_FIELD)
    return DEVIDD_ERR_OTHER;

  return DEVIDD_SUCCESS;
}

int32_t check_bus_port_format(char *str)
{
  int32_t i = 0;

  if (strlen(str) > LEN_BUS_PORT)
  {
    return DEVIDD_ERR_OTHER;
  }

  for (i = 0; i < LEN_BUS_PORT; i++)
  {
    /* A character is valid if and only if its format is hexadecimal
       and if it is not a lowercase */
    if (!isdigit(str[i]))
    {
      return DEVIDD_ERR_OTHER;
    } 
  }
  return DEVIDD_SUCCESS;
}

int32_t check_horaries_format(char *field)
{
  int32_t i;
  uint32_t len; 
  int32_t dash = DEVIDD_ERR_OTHER;

  len = strlen(field);

  if (len > LEN_FIELD)
  {
    return DEVIDD_ERR_OTHER;
  }

  for (i = 0; i < len; i++)
  {
    /* If not a digit, the character is unvalid */
    if (isdigit(field[i]) == 0)
    {
      return DEVIDD_ERR_OTHER;
    }
    if ((i != 0) && (i < len - 1) && field[i] == '-')
    {
      dash = DEVIDD_SUCCESS;
    }
  }

  /* If no dash was found, dash is set to DEVIDD_ERR */ 
  return dash;
}
int32_t check_field_format(char *field, int32_t i)
{
  switch(i)
  {
    case FIELD_MACHINE:
      check_machine_format(field);
      break;

    case FIELD_BUS:
    case FIELD_PORT:
      check_bus_port_format(field);
      break;

    case FIELD_SERIAL:
      check_serial_format(field);
      break;
    case FIELD_VENDOR:
    case FIELD_PRODUCT:
      check_vendor_product_format(field);
      break;
    case FIELD_BCD:
      check_bcd_format(field);
      break;
    case FIELD_HORARY:
      check_horaries_format(field);
      break;
  }
}

/* Rule format: 
   (accept:user):machine:bus:port:serial:vendor:product:bcd:horary
   - 8 fields
   - length field: max 64
 */ 
int32_t check_rule_format(char *rule)
{
  int32_t i = 0; 
  char *token;
  uint32_t field = 1;
  int32_t valid = DEVIDD_SUCCESS;

  token = malloc(DEVID_MAX_LEN);
  if (token == NULL)
  {
    return DEVIDD_ERR_MEM;
  }

  for (i = 0; token != NULL; i++)
  {
    if (i == 0)
    {
      token = strtok(rule, ":");
    }
    else
    {
      token = strtok(NULL, ":");
    }

    check_field_format(token, i);

    if (strlen(token) > LEN_FIELD)
    {
      syslog(LOG_ERR, "Rule %s invalid: field "%s" is too long",
             rule, token);
      valid = DEVIDD_ERR_OTHER;
      break; 
    }
  }
  if (i != NB_FIELD_COMPLETE_ID)
  {
    syslog(LOG_ERR, "Rule %s invalid: %d fields found, 7 expected",
           rule, (i + 1));
    valid = DEVIDD_ERR_OTHER;
  }

  free(token);

  return valid; 
}

int32_t check_complete_id_format(char *complete_id)
{
   
}

