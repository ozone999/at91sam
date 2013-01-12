/* drivers/power/dummy_battery.c
 *
 * Power supply driver for the system using AC supplied dummy_battery
 * Based on goldfish power supply driver goldfish_battery.c
 * Author: Kasim Ling <ling_kasim@yahoo.cn>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <asm/io.h>

struct dummy_battery_data {
	struct power_supply battery;
	struct power_supply ac;
};

/* temporary variable used between goldfish_battery_probe() and goldfish_battery_open() */
static struct dummy_battery_data *battery_data;

static int dummy_ac_get_property(struct power_supply *psy,
			enum power_supply_property psp,
			union power_supply_propval *val)
{
	int ret = 0;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = 1;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int dummy_battery_get_property(struct power_supply *psy,
				 enum power_supply_property psp,
				 union power_supply_propval *val)
{
	int ret = 0;

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = POWER_SUPPLY_STATUS_FULL;
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = POWER_SUPPLY_HEALTH_GOOD;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = 1;
		break;
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = 100; /*org:50*/
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static enum power_supply_property dummy_battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_CAPACITY,
};

static enum power_supply_property dummy_ac_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};


static int dummy_battery_probe(struct platform_device *pdev)
{
	int ret;
	struct dummy_battery_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL) {
		ret = -ENOMEM;
		goto err_data_alloc_failed;
	}

	data->battery.properties = dummy_battery_props;
	data->battery.num_properties = ARRAY_SIZE(dummy_battery_props);
	data->battery.get_property = dummy_battery_get_property;
	data->battery.name = "battery";
	data->battery.type = POWER_SUPPLY_TYPE_BATTERY;

	data->ac.properties = dummy_ac_props;
	data->ac.num_properties = ARRAY_SIZE(dummy_ac_props);
	data->ac.get_property = dummy_ac_get_property;
	data->ac.name = "ac";
	data->ac.type = POWER_SUPPLY_TYPE_MAINS;

	ret = power_supply_register(&pdev->dev, &data->ac);
	printk(KERN_INFO "Battery Status:AC =%d\n",ret);
	if (ret)
		goto err_ac_failed;

	ret = power_supply_register(&pdev->dev, &data->battery);
      	printk(KERN_INFO "Battery Status:Battery=%d\n",ret);
	if (ret)
		goto err_battery_failed;

	platform_set_drvdata(pdev, data);
	battery_data = data;

	return 0;

err_battery_failed:
	power_supply_unregister(&data->ac);
err_ac_failed:
	kfree(data);
err_data_alloc_failed:
	return ret;
}

static int dummy_battery_remove(struct platform_device *pdev)
{
	struct dummy_battery_data *data = platform_get_drvdata(pdev);

	power_supply_unregister(&data->battery);
	power_supply_unregister(&data->ac);

	kfree(data);
	battery_data = NULL;
	return 0;
}

static struct platform_driver dummy_battery_device = {
	.probe		= dummy_battery_probe,
	.remove		= dummy_battery_remove,
	.driver = {
		.name = "dummy-battery"
	}
};

static int __init dummy_battery_init(void)
{
	return platform_driver_register(&dummy_battery_device);
}

static void __exit dummy_battery_exit(void)
{
	platform_driver_unregister(&dummy_battery_device);
}

module_init(dummy_battery_init);
module_exit(dummy_battery_exit);

MODULE_AUTHOR("Ling Kasim ling_kasim@yahoo.cn");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Battery driver for system using AC supplied dummy battery");

