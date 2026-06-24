# 13 · 企业级权限重构:组织 → 团队 → 范围化 RBAC(GitHub / 飞书式)

> 目标:把当前"扁平单组织、所有人共用一套全局角色"的权限体系,升级为
> **"组织 → 团队 → 团队内角色"** 的范围化模型——团队负责人能读写管理**本团队内部**
> 的成员与资源,但**不能跨团队、不能碰组织级设置**。同时修掉"权限名字和实际功能对不上"。
>
> 本文是给主程审阅的方案,不含实现。先看 §0 诊断和 §9 待拍板决策。

---

## 0. 现状诊断(为什么必须重构)

调研结论(均有 file:line 依据,见 `auth/permissions.py`、`auth/models.py`、`auth/store.py`、
`adapters/api/deps.py`、`admin_routes.py`):

1. **扁平单组织 RBAC,零范围**
   - `User.role_id`(一人一角色)→ `Role.permissions`(权限点集合)→ `Principal.has(perm)`。
   - 鉴权只有一句:`deps.require(perm)` 判 `perm in principal.permissions`。**没有任何范围维度**
     ——有这个权限,就对全平台所有数据生效。所有成员实质共用一个组织。

2. **"组织架构 / 部门"是装饰品,不参与鉴权**
   - 有树形 `departments` 表 + `user.department_id`,但**没有任何端点按部门做访问控制**。
     部门只用于成员列表的展示与筛选。`sec_operator` 看得到**全部**事件,不分部门。

3. **名实不符:4 个"孤儿权限"——授权了也没用**
   | 权限点 | 标签 | 真相 |
   |---|---|---|
   | `policies.manage` | 编辑策略 | 后端只有 `GET /policies`(`policies.view`)。策略改 YAML 文件,**无写端点**。 |
   | `tools.manage` | 管控工具 | 后端只有 `GET /tools/calls`(`tools.view`)。**无管控端点**。 |
   | `supply.manage` | 处置供应链风险 | 后端只有 `GET /supply/scans`(`supply.view`)。**无处置端点**。 |
   | `eval.run` | 发起评测 | 评测是离线 CLI(`python -m fulcrum.eval`)。**无运行时端点**。 |
   - 角色页能把这些开关点亮,给人"配好了"的错觉,但后端根本不消费——这正是"名字和功能对不上"。

> 一句话:**权限 = 能做什么(有) × 在什么范围内能做(完全缺失)**;且"能做什么"里有 4 条是空头支票。

---

## 1. 标杆模型(GitHub + 飞书)

**GitHub**(组织 / 团队 / 仓库三层):
- 组织角色:Owner(全权)/ Member,可加**自定义组织角色**;
- **嵌套团队**:子团队**继承**父团队的访问权;**团队 maintainer** 可管理本团队成员与父子关系,但管不到组织设置;
- **仓库级角色**(俄罗斯套娃,递进):Read ⊂ Triage ⊂ Write ⊂ Maintain ⊂ Admin;
- **自定义仓库角色**:从某个基础角色出发 + 40 余个细粒度权限增删组合;
- **基础权限(base permission)**:组织对所有仓库的默认档(none/read/write/admin)。

**飞书**(组织 / 部门 / 子管理员):
- 超级管理员 + **子管理员 = 一组管理权限(角色)× 管理范围(可管的部门/成员子树)**;
- 用户组(把任意部门/成员聚成组再授权);通讯录可见范围。

**共同精髓**:授权是**二维**的——(操作能力) × (作用范围)。一个 SOC 组长 = "成员管理"能力 ×
"仅 SOC 子树"范围。我们现在只有第一维。

---

## 2. 目标模型(Fulcrum)

```
组织(Org,单租户实例)
├─ 组织级角色(全局):平台 Owner / 系统管理员  —— 跨团队的平台能力
│     · 改系统设置、定义角色、建/删团队、配 AI 模型 …(全局,无范围)
└─ 团队(Team,授权范围单元;由"部门"升格,保留树形,子团队继承父团队)
      ├─ 团队负责人(Maintainer):读写管理**本团队及子树**的成员/角色分配/团队内资源
      ├─ 团队成员(按团队级角色:运营员 / 审计员 / 只读 …)
      └─ 团队内资源(事件、策略、工具…按 team 归属;成员只见本团队范围)
```

要点:
- **团队 = 访问边界**(不再是装饰)。把现有 `departments` 升格为 `teams`(树形、子树继承不变)。
- **两类角色**:组织级(全局生效)与团队级(只在所属团队范围生效)。
- **团队负责人**对应 GitHub team maintainer / 飞书子管理员:**范围被钉死在本团队子树**。
- **资源归属团队**(P2):让"团队内读写"真正有意义——团队成员只看本团队的事件/策略。

---

## 3. 鉴权内核升级:`has(perm)` → `can(perm, scope)`

- **Principal 扩展**:除组织级权限集外,携带"每团队权限"——`team_perms: dict[team_id, frozenset[perm]]`,
  并按团队树展开**子树继承**(父团队负责人自动覆盖子团队)。
- **端点鉴权**:`require(perm)` → `require(perm, scope=resource.team_id)`:
  - 组织级权限:任意范围放行;
  - 团队级权限:仅当 `resource.team_id` ∈ 本人在该 perm 下可达的团队集合(含子树);
  - 列表类端点:按"可见团队集合"做**行级过滤**(team 不在可见集 → 不返回)。
- **fail-closed 不变**:范围解析不出 / 资源无归属又非组织级 → 拒。
- 落点:`adapters/api/deps.py` 的 `require`;`Principal` 模型;各路由把"资源 team 归属"传入。

> **AI 助手权限 = 与本人共享(铁律,主程明确)。** 助手不是独立身份,它**以当前登录者的 Principal
> 行事、继承其(已范围化的)权限**。因此团队范围天然套在助手上:操作员只能管本团队的人,
> 助手替他做也只能管本团队;操作员看不到别队事件,助手也看不到。落点:`AssistantAgent` 已收
> `principal`,`operation_registry.visible_for(principal)` 按权限过滤工具,**执行点的纵深复校
> 必须同样带 `scope`**(P1/P2 把 `can(perm, scope)` 接进助手工具执行,与人走同一套闸,不开后门)。

---

## 4. 权限目录重做(名实对齐)

**原则**:每个权限点必须能指向**一个真实端点**;且每条标注 `scope = org | team`。

- **先处置 4 个孤儿**(§0.3):二选一,逐条决定——
  - 补端点让它名副其实(如 `policies.manage` 真的能改策略、`eval.run` 真能发起评测),或
  - 从目录删除(不留假开关)。建议 P0 阶段**先删/先标注为"未实装"**,避免误授权。
- **拆分组织级 / 团队级两张表**(示意,最终以评审为准):

  | 范围 | 权限点 | gate 的真实能力 |
  |---|---|---|
  | org | `org.settings.manage` | 系统设置写 |
  | org | `org.roles.define` | 定义/编辑角色模板(原 `roles.manage`) |
  | org | `org.teams.manage` | 建/删/移动团队(原 `dept.manage` 升格) |
  | org | `org.ai.configure` | AI 模型接入配置 |
  | org | `org.overview.view` | 全局总览 |
  | team | `team.events.view/handle` | 本团队事件查看/处置 |
  | team | `team.policies.view/manage` | 本团队策略(待 P2 资源归属) |
  | team | `team.members.manage` | 本团队成员增改停(团队负责人) |
  | team | `team.members.invite/approve` | 邀请/审批加入本团队 |
  | team | `team.audit.view` | 本团队审计溯源 |

- **命名规范**:`<scope>.<resource>.<action>`,一眼可辨范围。旧→新映射表在实现 PR 里给全。

---

## 5. 数据模型变更

- `teams`(由 `departments` 升格;沿用 `parent_id` 树、`sort_order`)。
- `team_memberships(user_id, team_id, team_role)` —— **多对多**:一人可在多个团队、各持不同团队级角色。
- `users`:保留一个可空的**组织级角色** `org_role_id`(多数人为空 = 无平台级权限);团队归属移到 memberships。
- `roles`:加 `scope`(org|team)区分两类角色模板;`team_role` 取值如 maintainer/operator/auditor/viewer。
- **资源归属(P2)**:`events`(会话归属团队)、`policies`、`tools` 等加 `team_id`/`owner_team`。
- **迁移**:现有 `user.role_id` → 若是 super_admin/sys_admin 落 `org_role_id`,其余转成"在其部门对应团队里的团队级角色";现有 `departments` → `teams`;现有 6 内置角色按 §8 拆分。

---

## 6. 管理操作的范围约束(用户核心诉求)

落实"团队组长读写管理团队内部、不能跨团队":

- **成员页**:团队负责人只看到 / 只能管**本团队子树**成员;邀请、改团队内角色、停用——全部 `scope` 限定。
- **越界即拒**:团队负责人不能创建组织级角色、不能改系统设置、不能看别的团队的事件(行级过滤)。
- **账号审批下放**:可把"申请加入本团队"的审批权(`team.members.approve`)给团队负责人,超管不再是唯一审批人。

**情景演练**:SOC 组长张三 = 团队`SOC`的 maintainer。
- ✅ 在成员页只见 SOC 及其子组(监控值班组、IR)的人,可增删改停、改他们的团队角色;
- ✅ 处置 SOC 范围内的事件;
- ❌ 看不到攻防组的事件,改不了系统设置,定义不了新角色——这些是组织级,他没有。

---

## 7. 前端

- **角色页**:拆"组织角色 / 团队角色"两区;团队角色作为模板,分配在团队上。
- **团队页**(原"组织架构"):每个团队成为带"负责人 + 成员 + 团队角色"的实体,不再是纯展示树。
- **成员页**:按当前登录者"可管团队集合"过滤;团队负责人只见自己的人。
- **权限矩阵**:按 org/team 分组;**移除孤儿权限的假开关**(§4)。
- 复用现有三态(无 / 只读 / 读写)交互,但每格标注其范围。

---

## 8. 分阶段落地(避免一次性大爆炸)

- **P0 · 止血(小,先做)**:权限目录**名实对齐**——删/补/标注 4 个孤儿权限;矩阵不再显示无效开关;
  每个权限点写清"实际 gate 哪个端点"。**先把"名字对不上"修了**,1 个小 PR。
- **P1 · 范围化管理**:`teams`(升格 departments)+ `team_memberships` + 组织/团队角色二分;
  Principal 携团队范围;`require(perm, scope)` 内核;**成员/角色管理端点加范围约束**(团队负责人只管本团队)。
  资源暂不分租户(数据仍全局可见,但**管理操作已 scoped**)——已能兑现用户 80% 的诉求。
- **P2 · 资源租户化**:`events`/`policies`/`tools` 带 `team_id`,列表按可见团队**行级过滤**。最大的一步,单独评审。
- **P3 · 高级**:GitHub 式自定义团队角色(基础角色 + 细粒度增删)、嵌套团队继承细化、审批下放完善。

---

## 9. 关键决策(已定 · 企业行业标准)

> 主程定调"按企业行业标准、给政企用",据此拍板如下,不再悬而未决。

1. **"团队"语义 = 访问边界 + 资源归属(单一范围单元)。**
   团队既是"一拨人",也是"一组被保护系统/资源域"。政企场景里不同处室/局(公安、税务、民政)
   各护各的智能体,**彼此的流量与事件必须隔离**——所以**资源(被保护系统、其事件/策略)归属团队**,
   成员只看本团队范围。这等价于把"部门"升格成 GitHub 的 Team / 飞书子管理员的"管理范围",并叠加
   资源租户化。**P2 资源租户化纳入正式范围**(政企不做数据隔离等于没做)。

2. **一人多团队、多角色 = 是(多对多,GitHub 标准)。**
   政企组织是矩阵式,一个分析师可同时服务多个处室。`team_memberships(user, team, team_role)` 多对多;
   另保留可空的"组织级角色"给平台管理员。

3. **执行顺序:P0 → P1 → P2 → P3,均纳入目标**,按竞赛排期(2026-09-15)推进,每阶段可独立交付价值。
   P0 止血最先落,P2(租户化)是政企刚需不砍,但排在范围化管理(P1)之后。

---

## 10. 前端重构(学 GitHub / 飞书的信息架构)

**现状毛病**:角色页把"角色列表 + 成员 + 权限矩阵"挤在一个页面的三栏里,部门/角色/成员都塞进
同一页的 Tab,**没有"每个实体一张页"**,范围(org/team)在视觉上完全看不出来——所以"不太舒服"。

**学到的范式(GitHub 组织设置 / 飞书管理后台)**:
- **左侧分区导航**(GitHub 的 Access 区):`成员 People` / `团队 Teams` / `角色 Roles` /
  `角色分配 Role assignments` / `待审批` / `审计`。组织级与团队级**在 IA 上就分开**,scope 一眼可辨。
- **每个实体一张独立页,不再挤三栏**:
  - **团队页**(GitHub team page 式):顶部面包屑(支持嵌套团队)+ Tab `成员 / 子团队 / 被保护资源 / 设置`;
    页头显示**团队负责人(maintainer)**;负责人可在此管本团队。
  - **角色页**:`组织角色` 与 `团队角色` 两类分开;点进某角色 = 权限矩阵(按类目分组 + 复用现有
    无/只读/读写三态)+ "谁拥有此角色"(Users / Teams 两个 Tab,GitHub role assignments 式)。
  - **成员页**:干净可搜索可筛选的表;每行展示该成员的**所属团队 + 组织角色**;支持批量操作、邀请流。
- **角色分配是一等对象**:把"角色"指派给"用户**或**团队"(GitHub 的 New role assignment),
  而非只能逐人选角色。
- **通用**:处处可搜、空状态友好、批量勾选、面包屑;管理操作按当前登录者"可管团队"过滤
  (团队负责人进成员页只见自己的人)。

**重构落点**:`console/src/features/admin/` 由"单页多 Tab + 三栏"改为"分区导航 + 实体页"路由结构;
保留视觉语言(我们的蓝色/卡片/三态),只换信息架构与布局。

---

## 11. 执行顺序(可独立交付)

- **P0 · 止血(小)· ✅ 已落**:权限目录名实对齐。已移除 3 个**gate 不到任何东西**的孤儿权限
  (`tools.manage`/`supply.manage`/`eval.run`)及其在内置角色中的引用;矩阵据此自动收掉假开关。
  `policies.manage` 暂留(它仍 gate 旧规划器的高危示例 `policy.disable`,支撑"高危需二次确认/越权即拒"
  安全回归),已在 `permissions.py` 就地注释说明"无真写端点",待真策略管理(P3)或旧规划器退役时处置。
  → 权限点 21 → 18;544 用例全过。
- **P1 · 团队范围化**:`teams`(升格 departments)+ `team_memberships` 多对多 + 组织/团队角色二分;
  `Principal` 携团队范围(子树继承)+ `require(perm, scope)` 内核;成员/角色管理端点加范围约束
  (团队负责人只管本团队子树)。前端:成员/团队/角色三分区 + 实体页骨架。
- **P2 · 资源租户化**:`events`/会话/`policies` 等带 `team_id`,列表按可见团队**行级过滤**;
  网关侧"被保护系统 ↔ 团队"映射。政企数据隔离刚需。
- **P3 · 高级**:GitHub 式自定义团队角色(基础角色 + 细粒度增删)、嵌套团队继承细化、审批下放。

---

## 附:参考来源
- GitHub — Roles in an organization / Repository roles / About teams(嵌套团队继承、team maintainer、Read–Triage–Write–Maintain–Admin、自定义角色):
  https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization ·
  https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams ·
  https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization
- GitHub 自定义仓库角色(基础角色 + 40+ 细粒度权限):
  https://github.blog/changelog/2021-10-27-enterprise-organizations-can-now-create-custom-repository-roles/
- 飞书 — 创建管理员角色及分配权限 / 管理组织架构可见范围 / 用户组(子管理员=角色×管理范围):
  https://www.feishu.cn/hc/zh-CN/articles/360043495213 ·
  https://www.feishu.cn/hc/zh-CN/articles/360049067480 ·
  https://www.feishu.cn/hc/zh-CN/articles/360049067479
