# ARCH=x86_64
# export STAGING_DIR = /media/cuong/HDD3/Openwrt-24.10/staging_dir
# CC = /media/cuong/HDD3/Openwrt-24.10/staging_dir/toolchain-x86_64_gcc-13.3.0_musl/bin/x86_64-openwrt-linux-musl-gcc
# CFLAGS = -I//media/cuong/HDD3/Openwrt-24.10/staging_dir/target-x86_64_musl/usr/include
# LDFLAGS = -L//media/cuong/HDD3/Openwrt-24.10/staging_dir/target-x86_64_musl/usr/lib

ARCH=arm64
export STAGING_DIR = /media/cuong/HDD3//media/cuong/HDD3/Open_wrt_22.03_GOLDEN/Open_wrt_22.03/openwrt/staging_dir
CC = /media/cuong/HDD3/Open_wrt_22.03_GOLDEN/Open_wrt_22.03/openwrt/staging_dir/toolchain-aarch64_generic_gcc-11.2.0_musl/bin/aarch64-openwrt-linux-musl-gcc
CFLAGS = -I//media/cuong/HDD3/Open_wrt_22.03_GOLDEN/Open_wrt_22.03/openwrt/staging_dir/target-aarch64_generic_musl/usr/include
LDFLAGS = -L//media/cuong/HDD3/Open_wrt_22.03_GOLDEN/Open_wrt_22.03/openwrt/staging_dir/target-aarch64_generic_musl/usr/lib

TARGET_ACL = rule_manager
TARGET_PORT = port_manager
INIT_SCRIPT_ACL = acl_manager
INIT_SCRIPT_PORT = port_manager
OPENWRT_IP = 192.168.21.90

all:
	$(CC) $(CFLAGS) $(LDFLAGS) acl.c -o $(TARGET_ACL) -luci -lubox
	$(CC) $(CFLAGS) $(LDFLAGS) port.c -o $(TARGET_PORT) -luci -lubox
	scp port_manager rule_manager root@192.168.21.90:/
# all: $(TARGET_ACL) $(TARGET_PORT)

$(TARGET_ACL):
	$(CC) $(CFLAGS) $(LDFLAGS) acl.c -o $(TARGET_ACL) -luci -lubox

$(TARGET_PORT):
	$(CC) $(CFLAGS) $(LDFLAGS) port.c -o $(TARGET_PORT) -luci -lubox

deploy: all
	scp $(TARGET_ACL) root@$(OPENWRT_IP):/usr/bin/acl
	scp $(TARGET_PORT) root@$(OPENWRT_IP):/usr/bin/port_acl
	scp $(INIT_SCRIPT_ACL) root@$(OPENWRT_IP):/etc/init.d/
	scp $(INIT_SCRIPT_PORT) root@$(OPENWRT_IP):/etc/init.d/
	ssh root@$(OPENWRT_IP) "chmod +x /etc/init.d/$(INIT_SCRIPT_ACL)"
	ssh root@$(OPENWRT_IP) "chmod +x /etc/init.d/$(INIT_SCRIPT_PORT)"
	@echo "Deployed both ACL and Port managers to OpenWrt device!"
	@echo "To enable auto-start on boot, run on device:"
	@echo "  /etc/init.d/$(INIT_SCRIPT_ACL) enable"
	@echo "  /etc/init.d/$(INIT_SCRIPT_PORT) enable"
	@echo "To start the services now, run on device:"
	@echo "  /etc/init.d/$(INIT_SCRIPT_ACL) start"
	@echo "  /etc/init.d/$(INIT_SCRIPT_PORT) start"

install_service:
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_ACL) enable"
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_ACL) start"
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_PORT) enable"
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_PORT) start"
	@echo "Both services installed and started!"

deploy_acl: $(TARGET_ACL)
	scp $(TARGET_ACL) root@$(OPENWRT_IP):/usr/bin/acl
	scp $(INIT_SCRIPT_ACL) root@$(OPENWRT_IP):/etc/init.d/
	ssh root@$(OPENWRT_IP) "chmod +x /etc/init.d/$(INIT_SCRIPT_ACL)"

deploy_port: $(TARGET_PORT)
	scp $(TARGET_PORT) root@$(OPENWRT_IP):/usr/bin/port_acl
	scp $(INIT_SCRIPT_PORT) root@$(OPENWRT_IP):/etc/init.d/
	ssh root@$(OPENWRT_IP) "chmod +x /etc/init.d/$(INIT_SCRIPT_PORT)"

status:
	@echo "=== ACL Manager Status ==="
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_ACL) status"
	@echo ""
	@echo "=== Port Manager Status ==="
	ssh root@$(OPENWRT_IP) "/etc/init.d/$(INIT_SCRIPT_PORT) status"

reload_acl:
	ssh root@$(OPENWRT_IP) "/usr/bin/acl reload"

reload_port:
	ssh root@$(OPENWRT_IP) "/usr/bin/port_acl reload"

reload: reload_acl reload_port

clean:
	rm -f $(TARGET_ACL) $(TARGET_PORT)