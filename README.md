# SFilter-OpenVPN


```
SFilter-OpenVPN is a script that automatically whitelists people who connect to OpenVPN, saving them forever. It drops the port while still allowing clients to connect, preventing annoying socket floods.
```

## Setup

1. Locate your OpenVPN `server.conf` file, which is commonly found in `/etc/openvpn/server/server.conf`.

2. Add the following lines to the `server.conf` file:

   ```conf
   status openvpn-status.log 2
   ```
3. Restart the openvpn service.
   ```
   sudo systemctl restart openvpn-server@server.service
   ```

## Recommendations

Locate the `push` line in your `server.conf` file and replace it with the following line to only allow TUN traffic (credits to toxicj for this):

```conf
push "redirect-gateway def1 bypass-dhcp"
```

This ensures that only the necessary traffic is allowed through the VPN tunnel, providing a more secure and stable connection.

