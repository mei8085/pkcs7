# 安全分析报告：PKCS#7/CMS 链验证中的签名时间（Signing Time）信任问题

- **分析对象**：`github.com/smallstep/pkcs7`（当前分支 `task/134`，基线提交 `442a684`）
- **分析日期**：2026-11-17
- **分析范围**：CMS `SigningTime` 认证属性从报文解析到证书链验证的完整数据流，以及以该属性作为验证时间的安全后果
- **结论摘要**：`VerifyWithChain()` 把**签名者自报的、不可信的** `SigningTime` 属性直接作为证书链验证时间传入 `x509.VerifyOptions.CurrentTime`。该属性虽受签名保护、第三方无法篡改，但值本身由签名者任意填写，签名者可以借此把验证时间移动到证书有效期内的任意时刻，使"过期/尚未生效"的时间约束失去意义。库中另提供的 `VerifyWithChainAtTime()` 使用调用方提供的可信时间，是安全的替代入口。库本身**不做任何吊销检查（CRL/OCSP）**，使该问题的影响进一步放大。

---

## 1. 背景：CMS 中的签名时间属性

### 1.1 属性定义

签名时间属性的 OID 定义在 `pkcs7.go:59`：

```go
OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
```

即 PKCS#9 `id-signingTime`（RFC 2315 §9.2、RFC 5652 §11.3）。它是 `SignerInfo` 的**认证属性（authenticated / signed attribute）**，与 `contentType`（1.2.840.113549.1.9.3）和 `messageDigest`（1.2.840.113549.1.9.4）并列。

### 1.2 签名时如何产生（写入端）

`sign.go:203-206`，`AddSignerChain()` 在构造认证属性集合时无条件写入签名者本机当前时间：

```go
attrs := &attributes{}
attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
attrs.Add(OIDAttributeMessageDigest, sd.messageDigest)
attrs.Add(OIDAttributeSigningTime, time.Now().UTC())
```

随后这些属性经 DER 编码后被私钥签名（`sign.go:223` → `signAttributes()`，`sign.go:398-423`），并放入 `signerInfo.AuthenticatedAttributes`（`sign.go:227-235`）。

**关键点**：库的写入端填的是真实当前时间，但报文格式本身允许任何持有私钥的一方在重新签名时填入任意时间值。该属性没有任何第三方（时间戳机构、信任锚）背书。

---

## 2. 签名时间从 CMS 内容进入链验证的完整路径

### 2.1 解析阶段：报文 → 内存结构

```
Parse(data)                                  pkcs7.go:176
  └─ ber2der(data)                           ber.go（BER→DER 规范化）
  └─ asn1.Unmarshal → contentInfo
  └─ parseSignedData(info.Content.Bytes)     verify.go:213
       └─ sd.SignerInfos → p7.Signers        verify.go:249-254
          （signerInfo.AuthenticatedAttributes 原样保留，verify.go 中定义于 sign.go:105-113）
```

解析阶段对属性不做任何语义校验，`SigningTime` 只是 `SignerInfo` 中一段待解码的 ASN.1 字节。

### 2.2 验证阶段：两条入口、两种时间来源

库暴露三个公开验证入口（`verify.go:18-57`）：

| API | 链验证所用时间 | 时间来源可信度 |
|---|---|---|
| `Verify()` → `VerifyWithChain(nil)` | 同下（但信任库为 nil，**不做链验证**） | — |
| `VerifyWithChain(truststore)` | **CMS 中的 `SigningTime` 属性**；属性缺失时退回 `time.Now().UTC()` | **不可信（签名者自报）** |
| `VerifyWithChainAtTime(truststore, currentTime)` | 调用方显式传入的 `currentTime`，文档明确声明 *"It does not use the signing time authenticated attribute"*（`verify.go:45-46`） | 可信（取决于调用方） |

#### 路径 A（不可信）：`VerifyWithChain` → `verifySignature`

`verify.go:133-188`，逐步追踪：

1. **第 139 行**：默认时间初始化为验证方当前时间：
   ```go
   signingTime := time.Now().UTC()
   ```
2. **第 140-176 行**：若存在认证属性，先校验 `messageDigest` 与内容哈希一致（第 143-160 行），然后：
   ```go
   err = unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
   if err == nil {
       // signing time found, performing validity check
       if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
           return &SigningTimeNotValidError{...}
       }
   }
   ```
   `unmarshalAttribute`（`verify.go:361-369`）直接 `asn1.Unmarshal` 属性值——**时间值完全取自报文**。唯一的检查是它必须落在签名者证书自身的 `NotBefore/NotAfter` 内。
3. **第 177-182 行：污点到达链验证**：
   ```go
   if truststore != nil {
       _, err = verifyCertChain(ee, p7.Certificates, truststore, signingTime)
   }
   ```
4. `verifyCertChain`（`verify.go:262-278`）把该值原样放入标准库选项：
   ```go
   verifyOptions := x509.VerifyOptions{
       Roots:         truststore,
       Intermediates: intermediates,
       KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
       CurrentTime:   currentTime,   // ← 攻击者控制的时间
   }
   chains, err = ee.Verify(verifyOptions)
   ```

Go 标准库 `x509.Certificate.Verify` 使用 `CurrentTime`（零值时内部退回 `time.Now()`）对链上**每一张证书**（EE、中间 CA、根）执行 `NotBefore/NotAfter` 有效期判断。因此报文中的一个属性最终决定了整条链的时间有效性判定。

#### 路径 B（可信）：`VerifyWithChainAtTime` → `verifySignatureAtTime`

`verify.go:74-131` 结构与路径 A 相同，但有本质区别：

- 链验证时间是函数参数 `currentTime`（第 121 行），**不被报文覆盖**；
- 报文中的 `SigningTime` 即使存在，也只用于第 108-118 行对 EE 证书的有效期一致性检查，不参与链验证。

也就是说，可信时间与不可信声明在代码中是两条独立的路径，库已经提供了正确的机制，但默认的 `VerifyWithChain` 选择了不可信的那条。

### 2.3 数据流污点图

```
CMS 报文（攻击者可控字节）
  └─ Parse → signerInfo.AuthenticatedAttributes
       └─ unmarshalAttribute(OIDAttributeSigningTime)   verify.go:165
            └─ signingTime（污点变量）
                 ├─ EE 证书有效期边界检查（自证循环）     verify.go:168-174
                 └─ verifyCertChain(..., signingTime)    verify.go:178
                      └─ x509.VerifyOptions.CurrentTime  verify.go:271
                           └─ crypto/x509 对整条链做 NotBefore/NotAfter 判定
```

---

## 3. 可信验证时间与不可信声明的安全后果对比

### 3.1 为什么"签名保护"不等于"时间可信"

`SigningTime` 是认证属性，修改它会使 `EncryptedDigest` 签名失效——**第三方在没有私钥的情况下无法篡改**。但这只保证了"属性确实由私钥持有者签署"，并不保证"这个时钟值是真实的"：

1. **签名者就是潜在攻击者**。安全模型必须容忍签名者谎报时间。签名证明的是数据来源与完整性，时间的真实性需要独立于签名者的信任源（见第 4 节）。
2. 持有（或曾经持有）合法私钥的一方，可以在一次合法签名中把时间写成证书有效期内的**任意时刻**，产物在密码学上完全有效。
3. 唯一的约束检查（`verify.go:168-174` / `111-117`）是"自报时间落在 EE 证书有效期内"。这是一个**循环论证**：它用攻击者自己填写的时间去证明证书在该时间有效，而真正要回答的问题——"签名发生时证书是否有效"——恰恰被这个自证跳过了。

### 3.2 具体攻击场景

**场景 1：过期证书继续"有效"（最直接）**

- EE 证书有效期为 2024-01-01 至 2025-01-01，私钥在 2025-06 泄露或证书到期后未续费。
- 攻击者 2026 年构造 CMS，`SigningTime` 填 `2024-06-01T00:00:00Z`，用该私钥正常签名。
- 受害者调用 `VerifyWithChain(truststore)`：自报时间在 EE 有效期内 → 边界检查通过 → `x509.Verify` 在 2024-06-01 时刻验证，链上所有证书当时均未过期 → **验证成功**。
- 若用当前真实时间（`VerifyWithChainAtTime(truststore, time.Now())`）验证，同一报文会因 EE 过期而失败。

**场景 2：尚未生效的证书被提前使用**

- 证书 `NotBefore` 在未来（预签发、密钥轮换提前部署）。攻击者把 `SigningTime` 写到 `NotBefore` 之后即可通过；真实时间验证本应拒绝。

**场景 3：历史重放与"背签"（backdating）**

- 证书生命周期为一年，但攻击者可以让 2026 年签署的报文呈现为 2020 年的签名，用于欺诈性声明（合同/审计日志/软件包时间戳造假）。链验证同样会通过——只要填写的时间点落在链上所有证书有效期的交集内。
- 注意边界检查只针对 **EE 证书**（`verify.go:168` 用的是 `ee.NotBefore/ee.NotAfter`）；但传入 `verifyCertChain` 后标准库会检查**全链**。因此攻击者选取的时间只需落在全链有效期交集内，长有效期 CA 的存在使可选时间窗口往往长达数年。

**场景 4：与缺失的吊销检查叠加**

- 全库检索确认：`p7.CRLs` 仅在 `parseSignedData` 中被存储（`verify.go:252`），`verifyCertChain` 的 `x509.VerifyOptions` 没有任何 CRL/OCSP 设置（`verify.go:267-272`），验证流程**完全不检查吊销状态**。
- 后果：一张已被 CA 吊销的证书，只要私钥可用，配合自报时间，链验证依然通过。即便未来加入吊销检查，CRL 的 `thisUpdate/nextUpdate` 与 OCSP 响应的时间判断同样依赖"当前时间"——若继续采信自报时间，攻击者可把时间移到吊销日期之前绕过吊销。时间源是吊销机制生效的前提。

**场景 5：多签名者情形**

- `VerifyWithChain` 对 `p7.Signers` 逐个调用 `verifySignature`（`verify.go:33-37`），每个 SignerInfo 携带各自独立的 `SigningTime`，攻击面按签名者数量倍增，任一签名者都可独立操纵自己的验证时间。

### 3.3 两种时间源的后果对照

| 维度 | 不可信：`SigningTime` 属性（路径 A） | 可信：调用方时间（路径 B） |
|---|---|---|
| 时间值控制方 | 签名者（报文作者） | 验证方/外部信任源 |
| 第三方篡改 | 受签名保护，无法在无密钥情况下篡改 | 不经过报文，无从篡改 |
| 签名者谎报 | **可任意谎报，无任何约束** | 不可能 |
| 过期 EE 证书 | 回填有效期内时间即可通过 | 按真实时间拒绝 |
| 未生效证书 | 前推时间即可通过 | 按真实时间拒绝 |
| 背签/重放 | 可伪造任意历史时间点 | 时间由验证方固定，无法伪造 |
| 吊销检查（当前缺失） | 未来即使实现也会被时间操纵绕过 | 可与 CRL/OCSP 时间窗口正确协同 |
| 适用语义 | 仅可作为"签名者声称的时间"展示，不可作为安全判定依据 | 适合做有效期、吊销、新鲜度等一切安全判定 |

### 3.4 库当前行为的定性

这不是内存破坏类漏洞，而是**信任边界设计缺陷（CWE-345：Insufficient Verification of Data Authenticity / CWE-295：Improper Certificate Validation 的时间维度）**：

- 文档注释（`verify.go:26-28`）已明确承认该行为：*"When the PKCS7 object includes the signing time authenticated attr verifies the chain at that time and UTC now otherwise."* 属于**已知并有意为之的设计**，但文档未警示其不可信语义，调用方极易误以为这是安全的默认值。
- 缓解性事实：属性受签名保护，因此攻击能力限定在"持有合法私钥的签名者"或"密钥泄露后的攻击者"，不构成无密钥的通用伪造。但在密钥泄露、证书到期、证书吊销这些恰恰最需要时间约束发挥作用的场景里，该机制恰好失效。

---

## 4. 时间策略如何防止篡改

核心原则：**安全判定所用的时间必须来自签名者控制范围之外的信任源；签名者自报时间只能作为非安全用途的声明。** 具体策略分层如下。

### 4.1 验证侧：默认使用可信时间（本库可立即落地）

1. **新代码一律使用 `VerifyWithChainAtTime(truststore, t)`**，其中 `t` 来自验证方受控时钟（`time.Now()`，配合单调时钟/NTP 认证）。该 API 已存在且语义正确（`verify.go:47`），文档明确不使用签名时间属性。
2. **将 `VerifyWithChain` 的语义视为遗留/危险入口**：
   - 短期：在其文档注释中明确警告"链验证时间取自不可信的报文属性，不能防止签名者背签，安全场景应改用 `VerifyWithChainAtTime`"；
   - 中期可考虑废弃（deprecate）该入口，或增加选项让调用方显式选择是否采信 `SigningTime`，默认关闭。
3. `Verify()`（信任库为 nil）本就不做链验证，仅校验签名与摘要，不受本问题直接影响；但应在文档中说明它不提供任何证书有效性保证。

### 4.2 新鲜度窗口（skew 容忍）策略

当业务允许使用报文携带的时间时（如日志、事件流），不要直接采信，而是施加验证方主导的窗口约束：

```
可信时间 T_now（验证方时钟）
要求： T_now - max_skew ≤ SigningTime ≤ T_now + max_skew
```

- `max_skew` 取分钟级时钟偏差容忍（如 5 分钟），而非证书有效期级；
- 超出窗口即拒绝。这样自报时间只能在狭小窗口内波动，无法回填到数年前的有效期内，场景 1/3 的攻击空间被压缩到可忽略。
- 窗口检查必须在验证方代码中、用可信时钟实施，不能由报文自身携带的字段证明。

### 4.3 可信时间戳（RFC 3161 / RFC 5544）——防止背签的标准方案

当业务确实需要证明"签名发生在某一历史时刻"（长期签名、代码签名、归档），正确做法是**第三方时间戳**而非 PKCS#9 `signingTime`：

1. 签名者对 CMS 签名后，把签名值（或其 imprint）发给可信时间戳机构（TSA）；
2. TSA 用自己的私钥签发 `TimeStampToken`（本身是一个 CMS SignedData，含 TSA 证书链与真实时间），作为**非签名属性（unsigned attribute）**嵌入 SignerInfo（RFC 3161 §2.3 规定该绑定；属性 OID `1.2.840.113549.1.9.16.2.14`，`id-aa-timeStampToken`，定义于 RFC 3161 附录 A，OID 弧源自 RFC 2634 ESS）；
3. 验证时：
   - TSA 是独立信任锚，签名者无法影响 TSA 写入的时间；
   - 校验 TSA 签名链、TSA 证书的时间戳专用 EKU、以及 imprint 与签名值的绑定；
   - 以 TSA 时间（而非 `signingTime`）作为历史验证时刻，再在该时刻验证签名者证书链，并结合该时刻可用的吊销数据（归档 CRL/OCSP 证据）判断有效性。

与本库现状的差距：当前库只处理 PKCS#9 `signingTime`，**没有任何 RFC 3161 时间戳的生成或验证代码**（全库无 `timeStampToken` 相关 OID 与处理逻辑）。这是能力缺口，也是建议的演进方向。

### 4.4 两种属性的本质区别（策略依据）

| | PKCS#9 `signingTime`（现状） | RFC 3161 `timeStampToken`（目标） |
|---|---|---|
| 时间填写方 | 签名者本人 | 独立 TSA |
| 信任锚 | 无（自证） | TSA 根证书 |
| 篡改/谎报 | 签名者可任意填写 | 签名者无法影响；TSA 签名防第三方篡改 |
| 可否作为链验证时间 | 不可以 | 可以（校验通过后） |
| 防背签 | 不能 | 能 |

### 4.5 与吊销、链验证的协同

1. **补齐吊销检查**：在 `verifyCertChain` 的 `VerifyOptions` 之外增加 CRL/OCSP 校验（库已解析 `p7.CRLs` 但未使用），且吊销判定的"当前时间"必须取自第 4.1/4.3 节的可信时间，否则吊销可被自报时间绕过。
2. **全链时间一致性**：注意现有边界检查只覆盖 EE（`verify.go:168`），可信时间进入 `x509.Verify` 后才覆盖中间 CA 与根；策略上应统一依赖标准库在可信时间下的全链判定，不要把 EE 级别的自证检查当作充分条件。
3. **时间属性的解析健壮性**：`unmarshalAttribute` 直接对属性值 `asn1.Unmarshal` 到 `time.Time`（`verify.go:165`），未限制时间类型（RFC 2315 要求 UTCTime；RFC 5652 对 1950-2049 用 UTCTime、之外用 GeneralizedTime）。策略上应校验标签类型与年份范围，拒绝畸形/越界时间值，避免解析歧义被利用。
4. **去重与单一事实源**：若报文含多个 `signingTime` 属性，`unmarshalAttribute` 只取第一个匹配项（`verify.go:362-367`），应显式拒绝重复属性，防止解析差异类攻击。

---

## 5. 发现清单与建议优先级

| # | 发现 | 位置 | 严重度 | 建议 |
|---|---|---|---|---|
| 1 | 不可信的 `SigningTime` 直接驱动 `x509.VerifyOptions.CurrentTime`，签名者可操纵链验证时间 | `verify.go:165,178,271` | **高**（信任边界缺陷，限持有/曾持有私钥者利用） | 安全场景改用 `VerifyWithChainAtTime`；废弃或警告 `VerifyWithChain` |
| 2 | 对 `SigningTime` 的唯一约束是 EE 证书自证式有效期检查，属循环论证 | `verify.go:168-174` | 中 | 保留为一致性检查但不作为安全保证；增加验证方主导的新鲜度窗口 |
| 3 | 全库无 CRL/OCSP 吊销检查，`CRLs` 字段只存不用 | `verify.go:252,267-272` | 高（与 #1 叠加放大） | 引入吊销检查，并以可信时间驱动吊销时刻判断 |
| 4 | 无 RFC 3161 可信时间戳支持，无法防背签 | 全库缺失 | 中（能力缺口） | 增加 `TimeStampToken` 嵌入与验证，以 TSA 时间作为历史验证时刻 |
| 5 | 时间属性未做标签/年份/重复属性校验 | `verify.go:165,361-369` | 低 | 限制 UTCTime/GeneralizedTime 类型与范围，拒绝重复属性 |
| 6 | 文档未警示 `VerifyWithChain` 的时间不可信语义 | `verify.go:22-28` | 中（误用风险） | 补充安全说明与迁移指引 |

### 建议的调用方迁移模式

```go
// 不推荐：链验证时间由报文作者控制
// err := p7.VerifyWithChain(truststore)

// 推荐：验证方受控时间，报文 SigningTime 不参与链验证
err := p7.VerifyWithChainAtTime(truststore, time.Now().UTC())

// 需证明历史签署时刻时：验证 RFC 3161 TimeStampToken，
// 以 TSA 时间 t 调用 VerifyWithChainAtTime(truststore, t)，
// 并在 t 时刻结合归档吊销数据判定
```

---

## 6. 参考依据

- RFC 5652 *Cryptographic Message Syntax (CMS)*，§11.3（signed attributes）、§5.3（SignerInfo）
- RFC 2315 *PKCS #7*，§9.2（PKCS#9 `signingTime` 定义）
- RFC 3161 *X.509 PKI Time-Stamp Protocol (TSP)*，§2.3（TimeStampToken 作为 SignerInfo 非签名属性的绑定）、附录 A（`id-aa-timeStampToken` OID 定义）
- RFC 2634 *Enhanced Security Services for S/MIME (ESS)*（`id-aa` OID 弧来源）
- Go 标准库 `crypto/x509.VerifyOptions.CurrentTime` 语义（零值退回当前时间，作用于全链有效期判定）
- 本库代码：`verify.go:47-57, 74-131, 133-188, 262-278, 361-369`；`sign.go:203-206, 398-423`；`pkcs7.go:59`；测试 `verify_test.go:42-137`（`TestInvalidSigningTime`）、`verify_test.go:503-534`（Firefox 附加组件链验证，注释明确 "verifies at the signingTime authenticated attr"）
