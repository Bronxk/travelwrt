# OpenWrt Package Makefile for GL.iNet Style Interface
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-glinet-style
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=Your Name <your.email@example.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-glinet-style
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=GL.iNet Style Router Interface
  DEPENDS:=+luci-base +luci-lib-jsonc +luci-lib-nixio +uhttpd +uhttpd-mod-lua
  PKGARCH:=all
endef

define Package/luci-app-glinet-style/description
  Modern, user-friendly web interface for OpenWrt routers inspired by GL.iNet design.
  Features intuitive wizards, real-time monitoring, and mobile-responsive layout.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-glinet-style/conffiles
/etc/config/glinet_interface
endef

define Package/luci-app-glinet-style/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/etc/config/glinet_interface $(1)/etc/config/
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/glinet-interface $(1)/etc/init.d/
	
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/40_luci-glinet-style $(1)/etc/uci-defaults/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/glinet
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/glinet/api.lua $(1)/usr/lib/lua/luci/controller/glinet/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/glinet
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/glinet/system.lua $(1)/usr/lib/lua/luci/model/glinet/
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/glinet/network.lua $(1)/usr/lib/lua/luci/model/glinet/
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/glinet/auth.lua $(1)/usr/lib/lua/luci/model/glinet/
	
	$(INSTALL_DIR) $(1)/www/glinet
	$(CP) ./files/www/glinet/* $(1)/www/glinet/
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/glinet-interface.json $(1)/usr/share/rpcd/acl.d/
	
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/glinet-ws-server $(1)/usr/bin/
endef

define Package/luci-app-glinet-style/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# Enable and start the service
	/etc/init.d/glinet-interface enable
	/etc/init.d/glinet-interface start
	
	# Configure uhttpd to serve our interface
	uci set uhttpd.glinet=uhttpd
	uci set uhttpd.glinet.listen_http='0.0.0.0:8080'
	uci set uhttpd.glinet.home='/www/glinet'
	uci set uhttpd.glinet.index_page='index.html'
	uci set uhttpd.glinet.cgi_prefix='/api'
	uci set uhttpd.glinet.lua_prefix='/api'
	uci set uhttpd.glinet.lua_handler='/usr/lib/lua/luci/controller/glinet/api.lua'
	uci commit uhttpd
	
	# Restart uhttpd
	/etc/init.d/uhttpd restart
	
	# Add firewall rule for port 8080
	uci add firewall rule
	uci set firewall.@rule[-1].name='Allow-GLiNet-WebUI'
	uci set firewall.@rule[-1].src='lan'
	uci set firewall.@rule[-1].proto='tcp'
	uci set firewall.@rule[-1].dest_port='8080'
	uci set firewall.@rule[-1].target='ACCEPT'
	uci commit firewall
	/etc/init.d/firewall restart
	
	echo "GL.iNet Style Interface installed successfully!"
	echo "Access the interface at: http://192.168.1.1:8080"
	echo "Default credentials: admin/admin"
}
exit 0
endef

define Package/luci-app-glinet-style/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/glinet-interface stop
	/etc/init.d/glinet-interface disable
	
	# Remove uhttpd configuration
	uci delete uhttpd.glinet 2>/dev/null
	uci commit uhttpd
	/etc/init.d/uhttpd restart
	
	# Remove firewall rule
	local i=0
	while uci get firewall.@rule[$i] >/dev/null 2>&1; do
		if [ "$(uci get firewall.@rule[$i].name 2>/dev/null)" = "Allow-GLiNet-WebUI" ]; then
			uci delete firewall.@rule[$i]
			uci commit firewall
			/etc/init.d/firewall restart
			break
		fi
		i=$((i + 1))
	done
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-glinet-style))