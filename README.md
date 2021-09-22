# nginx-log-rotator

Nginx用のログ切り捨てツール.
Dockerで動くNginxプロセスがmtail用に吐くログを短縮するのが目的
シグナルは全てNginxへ送られる。exit_statusはnginxの終了コードと同じになる。

```sh
nginx_log_rotator --config /etc/log_rotate_config.yaml
```

## 設定例

`rotate_span`の単位は秒、`log_inherit_kilobytes`で
何kilobyte作り直したログファイルに受け継ぐか決められる。
最初の不完全な一行は切り捨てる。

```yaml
---
cmd:
  - nginx
  - "-g"
  - "'daemon off;'"
rotate_span: 1800
rotate_targets:
  - /var/log/mtail/access.log
log_inherit_kilobytes: 256
```
