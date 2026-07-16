# octo-mail 架构

octo-mail 是一个以 **change-log 为脊柱** 的多租户分布式邮件内核:每账户一条 append-only 变更日志是**顺序脊柱**——它以单调 seq 同时驱动 IMAP MODSEQ/CONDSTORE、JMAP state 与 QRESYNC VANISHED,并作为跨节点复制/通知的有序源;邮箱/消息状态(`messages`/`mailboxes`)与日志在**同一事务**内写入,互为一致的承重表。IMAP/JMAP/SMTP 是消费者,复制/HA 是运它。协议层原样复用成熟的纯协议库(dkim/spf/dmarc/imapclient/smtpclient/...)经 Go module 依赖(vendored)引入,内核坐在 PostgreSQL + S3 上。

## 目录即架构

顶层目录一一对应架构中的角色。`ls` 顶层就是读架构图:

```
cmd/            单一无状态节点二进制 (main + serve 装配 + 运维子命令)

core/           【真源层】不依赖任何协议或后端
  store/          内核接口 (Account/Tx/MessageQuery) + shape 类型 (Message/Flags/UID/ModSeq/Change/Comm)
  directory/      结构性租户隔离契约 (Directory/TenantScope/InboundTarget)

storage/        【实现层】把 core 接口坐到 PG+S3 上
  postgres/       store 实现:advisory-lock 写事务、changelog 编解码、投影、coordinator(LISTEN/NOTIFY)
    schema/       DDL 按概念拆分:01_directory 02_changelog(★顺序脊柱)03_projections(messages/mailboxes 承重表 + FTS/线程 派生视图)04_queue(queue_log 历史 + queue 调度投影)05_deliverability 06_reports_antiabuse
  blob/           正文存储:fs + s3(SigV4,内容寻址,ranged-GET)

projection/     【派生层】只读物化视图 worker:FTS、线程,可从 `messages` 承重表从零重建

protocol/       【消费者层】每协议一包,只绑定 core 接口
  imapd/ jmapd/ smtpd/ webapi/

mailflow/       【邮件流】邮件进出的流水线
  inbound/        鉴别(SPF/DKIM/DMARC/iprev/DNSBL) + 决策(信誉/greylist/subjectpass/ruleset/自适应阈值/forwarded)
  submit/         提交入队 + deliverer + dialer(多出口源IP绑定) + DSN
  queue/          出站队列:append-only queue_log(尝试历史)+ queue 调度投影(due-scan)+ 租约投递(FOR UPDATE SKIP LOCKED,投递受租约超时约束以避免重复发送)
  autoreply/      度假自动回复
  deliverability/ 可达性:DKIM签名/轮换、IP池/warmup、信誉隔离、FBL/VERP、DANE、MTA-STS、suppression、webhook、密钥加密

security/       【横切安全】
  auth/           argon2id + SCRAM-SHA-256
  acme/           ACME/autotls:单节点 tls-alpn-01(autotls 包装)+ 集群 leader-gated DNS-01(ClusterManager,证书存 acme_cache,全节点只读服务)
  privsep/        特权端口 bind-then-drop 降权

ops/            【运维】
  obs/            Prometheus metrics
  ha/             领导选举 (pg_advisory_lock 单活 + 崩溃故障切换)
  reportdb/       DMARC/TLS-RPT 报告摄入
  webadmin/       管理 JSON API + healthz
  mailboxops/     mbox 导入导出

webui/          浏览器 webmail (严格 TS → committed JS → go:embed)
junkfilter/     贝叶斯垃圾过滤 (贝叶斯库包装,per-account)

docs/           架构文档 + GAP 清单
```

依赖方向单向下沉:`protocol → core 接口 → storage 实现 → 基质(PG/S3)`,`mailflow/security/ops` 横切但不反向依赖 protocol。接口线以上不知 Postgres/S3 存在;基质层不知 IMAP 存在。

## change-log 脊柱(为什么这样分)

一个每账户单调计数器 `accounts.changelog_seq` 同时服务三视图:

- **IMAP MODSEQ/CONDSTORE**:`modseq == seq`;`CHANGEDSINCE n` = replay `seq>n`;`QRESYNC VANISHED` = `msg_expunge` 条目。
- **IMAP UID/UIDNEXT**:每邮箱独立,与 `msg_add` 同事务推进。
- **JMAP state**:`state = FormatInt(seq)`;`Email/changes sinceState=n` = 同一 replay 的另一个 renderer。

`schema/02_changelog.sql` 单独成文件并标注 ★顺序脊柱:每次状态变更都在**同一事务**内向它追加一条 seq 有序的条目,`ReplayChanges` 据此驱动跨节点通知、CONDSTORE `CHANGEDSINCE`、JMAP `Email/changes` 与 QRESYNC `VANISHED`。

**边界(不要误读)**:日志是*顺序与变更通知*的真源,不是*内容*的真源。`ChangeAddUID` 只携带 `mailbox_id/uid/modseq/flags/keywords`,**不含** `blob_ref/size/msg_prefix/email_id`——因此**无法**从日志单独重建 `messages`/`mailboxes`;这两张承重表与日志同事务写入,是并列的真源。`schema/03_projections.sql` 中真正“可 TRUNCATE + rebuild”的只有 FTS 与线程视图,且它们是折叠 `messages` 表(而非回放日志)重建的。

## 单写/并发

每账户 `pg_advisory_xact_lock(account_id)` 作为改账户事务的第一条语句,跨无状态节点串行化 seq/uid/modseq 分配;提交自动释放(崩溃即释放,正是 HA 需要的)。跨账户全并行(锁按账户,表按 account_id HASH 分区,Citus 等价)。

## 与上游协议库的关系

复用 mox 成熟的 ~23K LOC 纯协议**库**(dkim/spf/dmarc/smtp-wire/message/sasl/scram/dns/... 经 Go module 依赖 vendored 引入,`core/store/reuse_check.go` 编译期证明可绑定),不重造算法。但**服务器层是全新代码**:`protocol/{imapd,smtpd,jmapd,webapi}` 约 8.8K LOC 是针对 core 接口新写的薄消费层(mox 无 JMAP 服务器,jmapd 完全原创;mox 的 imapserver/smtpserver 也未被复用)。诚实表述:*协议库复用,服务器新写*。净增:JMAP 全协议、原生多租户(编译期对象可达性隔离)、水平扩展、change-log 统一 IMAP/JMAP/复制。详见 [gap.md](gap.md)。
