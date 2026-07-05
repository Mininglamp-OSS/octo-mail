# octo-mail 架构

octo-mail 是一个以 **change-log 为脊柱** 的多租户分布式邮件内核:每账户一条 append-only 变更日志是唯一真源,邮箱状态是它的投影,IMAP/JMAP/SMTP 是它的消费者,复制/HA 是运它。协议层原样复用成熟的纯协议库(dkim/spf/dmarc/imapclient/smtpclient/...)经 Go module `replace` 引入,内核坐在 PostgreSQL + S3 上。

## 目录即架构

顶层目录一一对应架构中的角色。`ls` 顶层就是读架构图:

```
cmd/            单一无状态节点二进制 (main + serve 装配 + 运维子命令)

core/           【真源层】不依赖任何协议或后端
  store/          内核接口 (Account/Tx/MessageQuery) + shape 类型 (Message/Flags/UID/ModSeq/Change/Comm)
  directory/      结构性租户隔离契约 (Directory/TenantScope/InboundTarget)

storage/        【实现层】把 core 接口坐到 PG+S3 上
  postgres/       store 实现:advisory-lock 写事务、changelog 编解码、投影、coordinator(LISTEN/NOTIFY)
    schema/       DDL 按概念拆分:01_directory 02_changelog(★真源) 03_projections(可重建) 04_queue(queue_log 真源+queue 投影) 05_deliverability 06_reports_antiabuse
  blob/           正文存储:fs + s3(SigV4,内容寻址,ranged-GET)

projection/     【派生层】日志的物化视图 worker:FTS、线程,可从零重建

protocol/       【消费者层】每协议一包,只绑定 core 接口
  imapd/ jmapd/ smtpd/ webapi/

mailflow/       【邮件流】邮件进出的流水线
  inbound/        鉴别(SPF/DKIM/DMARC/iprev/DNSBL) + 决策(信誉/greylist/subjectpass/ruleset/自适应阈值/forwarded)
  submit/         提交入队 + deliverer + dialer(多出口源IP绑定) + DSN
  queue/          出站队列:append-only queue_log(真源)+ queue 投影(due-scan)+ 租约投递(FOR UPDATE SKIP LOCKED)
  autoreply/      度假自动回复
  deliverability/ 可达性:DKIM签名/轮换、IP池/warmup、信誉隔离、FBL/VERP、DANE、MTA-STS、suppression、webhook、密钥加密

security/       【横切安全】
  auth/           argon2id + SCRAM-SHA-256
  acme/           ACME/autotls (autotls 包装)
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

`schema/02_changelog.sql` 单独成文件并标注 ★真源;`schema/03_projections.sql` 是可 `TRUNCATE + rebuild` 的物化视图——**schema 目录本身就讲清了哪些表是承重墙、哪些可重建**。

## 单写/并发

每账户 `pg_advisory_xact_lock(account_id)` 作为改账户事务的第一条语句,跨无状态节点串行化 seq/uid/modseq 分配;提交自动释放(崩溃即释放,正是 HA 需要的)。跨账户全并行(锁按账户,表按 account_id HASH 分区,Citus 等价)。

## 与上游协议库的关系

复用成熟的 ~20K LOC 纯协议库(经 module replace 引入),不重造算法;octo-mail 只做内核编织 + 服务实现。净增:JMAP 全协议、原生多租户(编译期对象可达性隔离)、水平扩展、change-log 统一 IMAP/JMAP/复制。详见 [gap.md](gap.md)。
