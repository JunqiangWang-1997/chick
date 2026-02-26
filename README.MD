# chick

基于 Incus 的“切鸡”脚本，支持 NATv6 + 独立 /128 IPv6，并自动配置容器内 SSH。

## 脚本说明

- `chick.sh`：主脚本（菜单 + 子命令）
- `mkchick.sh`：兼容入口，等价于 `chick.sh create <name>`
- `rmchick.sh`：兼容入口，等价于 `chick.sh delete <name>`

## 使用方式

先给执行权限：

```bash
chmod +x chick.sh mkchick.sh rmchick.sh
```

交互菜单：

```bash
./chick.sh
```

菜单包含：

1. 安装 Incus 和依赖
2. 配置网络（UPLINK、LAN 网络名、公网 IPv6 前缀）
3. 创建容器（切鸡）
4. 删除容器（删鸡）
5. 列出切鸡记录
6. 查看单个切鸡记录
7. 一键流程（安装 + 配置 + 切鸡）

非交互子命令：

```bash
./chick.sh install
./chick.sh network
./chick.sh create mychick
./chick.sh delete mychick
./chick.sh list
./chick.sh info mychick
./chick.sh oneshot mychick --uplink eth0 --lan-net lan0 --pub-prefix 2001:db8:1234:5678
```

`oneshot` 会自动执行安装与创建流程，缺失参数时会交互询问。

## 配置文件

- 路径：`/etc/chick.conf`
- 字段：`UPLINK`、`LAN_NET`、`PUB_PREFIX`

`PUB_PREFIX` 示例：`2001:db8:1234:5678`

## 注意事项

- 需要 root 权限运行。
- `PUB_PREFIX` 不能为空，否则无法分配公网 `/128` IPv6。
- 脚本会写入 `/etc/sysctl.d/99-chick.conf` 打开 IPv6 转发与代理 NDP。

## 状态文件

- 路径：`/var/lib/mkchick/chicks.tsv`
- 每次创建会写入或更新对应容器记录，每次删除会清理对应记录。
- 字段：
  `name`、`ipv6`、`lan_ipv4`、`password`、`ssh_ready`、`uplink`、`lan_net`、`created_at`、`image`
