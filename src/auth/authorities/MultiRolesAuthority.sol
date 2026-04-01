// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {Auth, Authority} from "../Auth.sol";

/// @notice Flexible and target agnostic role based Authority that supports up to 256 roles.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/authorities/MultiRolesAuthority.sol)
/*
 * 功能总结：
 * 灵活且与目标合约无关的多角色权限管理合约，支持最多 256 个角色（role0~255）。
 *
 * 核心特点：
 * - 继承 Auth（owner + Authority 双重权限）并实现 Authority 接口，可作为其他 Auth 合约的外部授权后端
 * - 使用 bytes32 位图（bitmap）管理角色分配和角色能力映射，极致节省 gas
 * - 支持三种授权判断路径：
 *   1. 目标合约自定义 Authority（getTargetCustomAuthority）—— 优先级最高
 *   2. 公开能力（isCapabilityPublic）—— 任何人都可调用
 *   3. 角色能力匹配（getUserRoles & getRolesWithCapability 位与运算）—— RBAC 核心
 * - 支持为特定目标合约设置独立的自定义 Authority，实现细粒度权限委托
 *
 * 权限体系位置：
 * Auth.requiresAuth() → Auth.isAuthorized() → Authority.canCall()
 *                                                      ↑
 *                                          MultiRolesAuthority.canCall()
 *                                          ├── getTargetCustomAuthority[target].canCall()
 *                                          ├── isCapabilityPublic[functionSig]
 *                                          └── getUserRoles[user] & getRolesWithCapability[functionSig]
 *
 * 位图设计：
 * - getUserRoles[user] 是一个 bytes32（256 bit），每一位代表一个角色
 *   例：bit 0 = role 0, bit 5 = role 5, bit 255 = role 255
 * - getRolesWithCapability[functionSig] 同理，每一位代表拥有该能力的角色
 * - 判断用户是否拥有某能力：两个 bytes32 做位与（&），非零即命中
 */
contract MultiRolesAuthority is Auth, Authority {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 用户角色变更事件
     * @param user    被变更角色的用户地址
     * @param role    角色编号（0~255）
     * @param enabled true=授予角色，false=撤销角色
     */
    event UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled);

    /*
     * @dev 公开能力变更事件
     * @param functionSig 函数选择器（4 字节）
     * @param enabled     true=设为公开（任何人可调用），false=取消公开
     */
    event PublicCapabilityUpdated(bytes4 indexed functionSig, bool enabled);

    /*
     * @dev 角色能力变更事件
     * @param role        角色编号（0~255）
     * @param functionSig 函数选择器（4 字节）
     * @param enabled     true=授予该角色此能力，false=撤销
     */
    event RoleCapabilityUpdated(uint8 indexed role, bytes4 indexed functionSig, bool enabled);

    /*
     * @dev 目标合约自定义 Authority 变更事件
     * @param target    目标合约地址
     * @param authority 新的自定义 Authority 合约地址（address(0) 表示清除）
     */
    event TargetCustomAuthorityUpdated(address indexed target, Authority indexed authority);

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 构造函数，透传给父合约 Auth
     * @param _owner     初始所有者地址
     * @param _authority 初始外部授权策略合约（可传 Authority(address(0)) 表示不启用）
     *
     * 设计决策：
     * - 构造函数体为空，所有初始化逻辑由 Auth 完成
     */
    constructor(address _owner, Authority _authority) Auth(_owner, _authority) {}

    /*//////////////////////////////////////////////////////////////
                     CUSTOM TARGET AUTHORITY STORAGE
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 目标合约 → 自定义 Authority 的映射
     *      为特定目标合约设置独立的权限判断合约，优先级最高
     *      当 canCall 查询某target 时，若此映射非零地址，直接委托给自定义 Authority 判断
     *
     * Key: address— 目标合约地址
     * Value: Authority — 自定义授权合约地址（address(0) 表示未设置）
     *
     * 示例：
     *   getTargetCustomAuthority[vaultAddress] = specialAuthority
     *   → 对vault合约的所有函数调用，权限判断委托给 specialAuthority
     */
    mapping(address => Authority) public getTargetCustomAuthority;

    /*//////////////////////////////////////////////////////////////
                            ROLE/USER STORAGE
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 用户地址 → 角色位图的映射
     *      每个用户对应一个 bytes32（256 bit），每一位代表是否拥有对应角色
     *      bit 位从右往左读：bit 0 = role 0, bit 1 = role 1, ..., bit 255 = role 255
     *
     * Key: address — 用户地址
     * Value: bytes32 — 角色位图
     *
     * 示例：
     *   getUserRoles[alice] = 0x...0000_0101
     *   → alice拥有 role 0（bit 0=1）和 role 2（bit 2=1）
     */
    mapping(address => bytes32) public getUserRoles;

    /*
     * @dev 函数选择器 → 是否公开的映射
     *      标记为 true 的函数，任何人都可以调用（无需角色）
     *
     * Key: bytes4 — 函数选择器
     * Value: bool  — true=公开，false=非公开
     *
     * 示例：
     *   isCapabilityPublic[bytes4(keccak256("balanceOf(address)"))] = true
     *   → balanceOf 函数对所有人开放
     */
    mapping(bytes4 => bool) public isCapabilityPublic;

    /*
     * @dev 函数选择器 → 角色能力位图的映射
     *      每个函数选择器对应一个 bytes32（256 bit），每一位代表哪个角色拥有此能力
     *
     * Key: bytes4  — 函数选择器
     * Value: bytes32 — 角色能力位图
     *
     * 示例：
     *   getRolesWithCapability[bytes4(keccak256("mint(address,uint256)"))] = 0x...0000_0110
     *   → role 1（bit 1=1）和 role 2（bit 2=1）拥有 mint 能力
     */
    mapping(bytes4 => bytes32) public getRolesWithCapability;

    /*
     * @dev 查询指定用户是否拥有指定角色
     * @param user 用户地址
     * @param role 角色编号（0~255）
     * @return bool true=拥有该角色
     *
     * 位运算拆解：
     *   uint256(getUserRoles[user]) >> role— 将目标 bit 右移到最低位
     *   & 1                    — 掩码取最低位
     *   != 0                — 判断是否为1
     *
     * 示例：getUserRoles[alice] = 0x...0101, role = 2
     *   0101 >> 2 = 0001 → 0001 & 1 = 1 → 1 != 0 → true（alice 拥有 role 2）
     */
    function doesUserHaveRole(address user, uint8 role) public view virtual returns (bool) {
        return (uint256(getUserRoles[user]) >> role) & 1 != 0;
    }

    /*
     * @dev 查询指定角色是否拥有指定函数能力
     * @param role角色编号（0~255）
     * @param functionSig 函数选择器（4 字节）
     * @return bool       true=该角色拥有此能力
     *
     * 位运算拆解：
     *   uint256(getRolesWithCapability[functionSig]) >> role  — 将目标 bit 右移到最低位
     *   & 1                                                    — 掩码取最低位
     *   != 0                                                   — 判断是否为 1
     */
    function doesRoleHaveCapability(uint8 role, bytes4 functionSig) public view virtual returns (bool) {
        return (uint256(getRolesWithCapability[functionSig]) >> role) & 1 != 0;
    }

    /*//////////////////////////////////////////////////////////////
                           AUTHORIZATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 核心授权判断函数，实现 Authority 接口
     * 判断 user 是否有权对target 合约调用 functionSig 函数
     * @param user        调用者地址
     * @param target      目标合约地址
     * @param functionSig 函数选择器（4 字节）
     * @return bool       true=授权通过
     *
     * 判断流程（三条路径，按优先级）：
     *   1. 检查 target 是否有自定义 Authority → 有则完全委托给它判断，直接返回
     *   2. 检查 functionSig 是否为公开能力 → 是则返回 true
     *   3. 位与运算：用户角色位图 & 函数能力位图 → 非零则至少有一个角色匹配
     *
     * 设计决策：
     * - 自定义 Authority 优先级最高，可实现对特定目标合约的完全权限接管
     * - 路径 2 和 3 使用短路或（||），公开能力命中后不再做位运算，节省 gas
     * - 位与运算一次性完成所有角色的匹配判断，无需循环遍历，O(1) 复杂度
     */
    function canCall(address user, address target, bytes4 functionSig) public view virtual override returns (bool) {
        // 路径 1：检查目标合约是否有自定义 Authority
        Authority customAuthority = getTargetCustomAuthority[target];

        // 若自定义 Authority 存在（非零地址），完全委托给它判断
        if (address(customAuthority) != address(0)) return customAuthority.canCall(user, target, functionSig);

        // 路径 2 || 路径 3：
        // isCapabilityPublic[functionSig]— 该函数是否公开
        // getUserRoles[user] & getRolesWithCapability[functionSig] — 用户角色与函数所需角色的位与
        // bytes32(0) != ... — 位与结果非零说明至少有一个角色匹配
        return
            isCapabilityPublic[functionSig] || bytes32(0) != getUserRoles[user] & getRolesWithCapability[functionSig];
    }

    /*///////////////////////////////////////////////////////////////
               CUSTOM TARGET AUTHORITY CONFIGURATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 为指定目标合约设置自定义 Authority
     * @param target          目标合约地址
     * @param customAuthority 自定义 Authority 合约地址（传 Authority(address(0)) 可清除）
     *
     * 权限：requiresAuth — 需要 owner 或 Authority 授权
     *
     * 设计决策：
     * - 允许为特定合约设置独立的权限判断逻辑，实现细粒度权限委托
     * - 设置后，canCall 中对该target 的查询将完全绕过角色/公开能力逻辑
     * - 传入 address(0) 可清除自定义 Authority，回退到角色/公开能力判断
     */
    function setTargetCustomAuthority(address target, Authority customAuthority) public virtual requiresAuth {
        // 存储目标合约的自定义 Authority
        getTargetCustomAuthority[target] = customAuthority;

        emit TargetCustomAuthorityUpdated(target, customAuthority);
    }

    /*//////////////////////////////////////////////////////////////
                  PUBLIC CAPABILITY CONFIGURATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 设置指定函数是否为公开能力（任何人可调用）
     * @param functionSig 函数选择器（4 字节）
     * @param enabled     true=设为公开，false=取消公开
     *
     * 权限：requiresAuth — 需要 owner 或 Authority 授权
     *
     * 设计决策：
     * - 公开能力是最宽松的权限级别，设置后无需任何角色即可调用
     * - 适用于只读查询函数或无安全风险的操作
     */
    function setPublicCapability(bytes4 functionSig, bool enabled) public virtual requiresAuth {
        // 更新公开能力状态
        isCapabilityPublic[functionSig] = enabled;

        emit PublicCapabilityUpdated(functionSig, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                       USER ROLE ASSIGNMENT LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 为指定用户授予或撤销指定角色
     * @param user    用户地址
     * @param role    角色编号（0~255）
     * @param enabled true=授予角色，false=撤销角色
     *
     * 权限：requiresAuth — 需要 owner 或 Authority 授权
     *
     * 位运算拆解（授予 role=3 为例）：
     *   bytes32(1<< 3) = 0x...0000_1000                — 构造 role 3 的掩码
     *   getUserRoles[user] |= 0x...0000_1000            — 按位或，将bit 3 置为 1
     *
     * 位运算拆解（撤销 role=3 为例）：
     *   bytes32(1 << 3) = 0x...0000_1000                — 构造 role 3 的掩码
     *   ~bytes32(1 << 3) = 0x...1111_0111— 取反，bit 3 变为 0，其余为 1
     *   getUserRoles[user] &= 0x...1111_0111            — 按位与，仅清除 bit 3，保留其他角色
     */
    function setUserRole(address user, uint8 role, bool enabled) public virtual requiresAuth {
        if (enabled) {
            // 授予角色：用按位或将对应 bit 置 1
            getUserRoles[user] |= bytes32(1 << role);
        } else {
            // 撤销角色：用按位与 + 取反将对应 bit 置 0
            getUserRoles[user] &= ~bytes32(1 << role);
        }

        emit UserRoleUpdated(user, role, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                   ROLE CAPABILITY CONFIGURATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 为指定角色授予或撤销指定函数的调用能力
     * @param role        角色编号（0~255）
     * @param functionSig 函数选择器（4 字节）
     * @param enabled     true=授予能力，false=撤销能力
     *
     * 权限：requiresAuth — 需要 owner 或 Authority 授权
     *
     * 位运算拆解（授予 role=2 对mint 的能力为例）：
     *   bytes32(1 << 2) = 0x...0000_0100                        — 构造 role 2 的掩码
     *   getRolesWithCapability[mintSig] |= 0x...0000_0100       — 按位或，将 bit 2 置为 1
     *
     * 位运算拆解（撤销 role=2 对 mint 的能力为例）：
     *   ~bytes32(1 << 2) = 0x...1111_1011                       — 取反
     *   getRolesWithCapability[mintSig] &= 0x...1111_1011       — 按位与，仅清除 bit 2
     */
    function setRoleCapability(uint8 role, bytes4 functionSig, bool enabled) public virtual requiresAuth {
        if (enabled) {
            // 授予能力：用按位或将对应 bit 置 1
            getRolesWithCapability[functionSig] |= bytes32(1 << role);
        } else {
            // 撤销能力：用按位与 + 取反将对应 bit 置 0
            getRolesWithCapability[functionSig] &= ~bytes32(1 << role);
        }

        emit RoleCapabilityUpdated(role, functionSig, enabled);
    }
}
