# Step 1: Development Environment Setup

## Virtual machines (VMware Workstation, Windows host)

| VM | Role | Resources |
| --- | --- | --- |
| Ubuntu 24.04 | Gateway (firewall node) | 4 GB RAM, 2 CPUs, 40 GB disk |
| Kali Linux | Test client | Host-only network |

## Network adapters on the Ubuntu gateway

| Interface | VMware adapter | Address | Role |
| --- | --- | --- | --- |
| ens33 | NAT (VMnet8) | 192.168.25.130/24 (DHCP) | Internet side |
| ens37 | Host-only (VMnet1) | 192.168.74.131/24 (DHCP) | Client side |

Check with:

    ip a
    ip route | grep default    # default route must use ens33

## Docker and Docker Compose

    sudo apt update
    sudo apt install docker.io
    sudo usermod -aG docker $USER    # then reboot
    sudo apt install docker-compose-v2
    docker --version                 # Docker 29.1.3
    docker compose version           # Docker Compose 2.40.3
    docker run hello-world

## Disk expansion (20 GB to 40 GB)

1. Delete any snapshots, then VMware: VM > Settings > Hard Disk > Expand to 40 GB.
2. Inside Ubuntu:

       sudo growpart /dev/sda 2
       sudo resize2fs /dev/sda2
       df -h /

## Problems and fixes

| Problem | Fix |
| --- | --- |
| apt: "Waiting for cache lock" | Background updates were running; wait, or reboot and retry |
| docker: "permission denied" on docker.sock | Add the user to the docker group, then reboot |
| docker.service failed after install | `sudo systemctl reset-failed docker`, `sudo systemctl restart containerd`, `sudo systemctl restart docker` |

