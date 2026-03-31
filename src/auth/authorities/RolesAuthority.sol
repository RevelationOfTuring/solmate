// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {Auth, Authority} from "../Auth.sol";

/// @notice Role based Authority that supports up to 256 roles.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/authorities/RolesAuthority.sol)
/// @author Modified from Dappsys (https://github.com/dapphub/ds-roles/blob/master/src/roles.sol)
/*
 * @title RolesAuthority —基于角色的权限管理合约（RBAC）
 * @notice 支持最多 256 个角色（role 0~255），通过位图（bitmap）高效存储和查询。
 *核心思路：
 *         1. 每个用户持有一个 bytes32 位图，每一位代表是否拥有对应角色
 *         2. 每个 (target, functionSig) 也有一个 bytes32 位图，表示哪些角色可以调用
 *         3. 两者做 & 运算，非零即表示用户有权调用
 *         另外支持将某个函数设为"公开"，任何人都可调用。
 *         继承 Auth 实现自身管理函数的权限控制，继承 Authority 对外提供 canCall 接口。
 */
contract RolesAuthority is Auth, Authority {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice 用户角色变更时触发
     * @param user被修改角色的用户地址
     * @param role    角色编号（0~255）
     * @param enabled true = 授予角色，false = 撤销角色
     */
    event UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled);

    /*
     * @notice 公开权限变更时触发
     * @param target      目标合约地址
     * @param functionSig 函数选择器（bytes4）
     * @param enabled     true = 设为公开，false = 取消公开
     */
    event PublicCapabilityUpdated(address indexed target, bytes4 indexed functionSig, bool enabled);

    /*
     * @notice 角色权限变更时触发
     * @param role角色编号（0~255）
     * @param target      目标合约地址
     * @param functionSig 函数选择器（bytes4）
     * @param enabled     true = 授予该角色调用权限，false = 撤销
     */
    event RoleCapabilityUpdated(uint8 indexed role, address indexed target, bytes4 indexed functionSig, bool enabled);

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice 构造函数，初始化 owner 和 authority（继承自 Auth）
     * @param _owner     合约所有者地址
     * @param _authority 外部权限合约（可传Authority(address(0)) 表示不使用）
     */
    constructor(address _owner, Authority _authority) Auth(_owner, _authority) {}

    /*//////////////////////////////////////////////////////////////
                            ROLE/USER STORAGE
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice 用户 → 角色位图
     * @dev bytes32 共256 位，第 N 位为 1 表示用户拥有角色 N
     *例如：位图值为 0x...05 (二进制 ...0101)，表示拥有角色 0 和角色 2
     */
    mapping(address => bytes32) public getUserRoles;

    // (目标合约, 函数选择器) → 是否为公开函数（任何人可调用）
    mapping(address => mapping(bytes4 => bool)) public isCapabilityPublic;

    /*
     * @notice (目标合约, 函数选择器) → 角色位图
     * @dev 第 N 位为 1 表示角色 N 可调用该函数
     */
    mapping(address => mapping(bytes4 => bytes32)) public getRolesWithCapability;

    /*
     * @notice 查询某用户是否拥有指定角色
     * @param user 用户地址
     * @param role 角色编号（0~255）
     * @return     true = 用户拥有该角色
     * @dev将位图转为 uint256 后右移 role 位，取最低位判断：(bitmap >> role) & 1
     */
    function doesUserHaveRole(address user, uint8 role) public view virtual returns (bool) {
        return (uint256(getUserRoles[user]) >> role) & 1 != 0;
    }

    /*
     * @notice 查询某角色是否有权调用指定合约的指定函数
     * @param role角色编号（0~255）
     * @param target      目标合约地址
     * @param functionSig 函数选择器
     * @return            true = 该角色可调用
     * @dev 与 doesUserHaveRole 相同的位移取位逻辑，操作对象为函数角色位图
     */
    function doesRoleHaveCapability(uint8 role, address target, bytes4 functionSig) public view virtual returns (bool) {
        return (uint256(getRolesWithCapability[target][functionSig]) >> role) & 1 != 0;
    }

    /*//////////////////////////////////////////////////////////////
                           AUTHORIZATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice Authority 接口实现 — 判断 user 是否有权调用 target 的functionSig
     * @param user调用者地址
     * @param target      目标合约地址
     * @param functionSig 函数选择器
     * @return            true = 允许调用
     * @dev 两个条件满足其一即可：
     *      1. 该函数被标记为公开（isCapabilityPublic）→ 短路返回，跳过位图运算
     *      2. 用户角色位图 & 函数所需角色位图 != 0（即至少有一个重叠的角色）
     */
    function canCall(address user, address target, bytes4 functionSig) public view virtual override returns (bool) {
        return
            // 条件 1：函数是否公开
            isCapabilityPublic[target][functionSig] ||
            // 条件 2：用户角色位图 AND 函数角色位图，非零则有权限
            // 注：用户角色位图 & 函数角色位图，只要 & 结果不全为 0，说明至少有一个角色既属于用户、又有权调用该函数 → 放行。
            bytes32(0) != getUserRoles[user] & getRolesWithCapability[target][functionSig];
    }

    /*//////////////////////////////////////////////////////////////
                   ROLE CAPABILITY CONFIGURATION LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice 设置某个函数是否为公开可调用（无需任何角色）
     * @param target      目标合约地址
     * @param functionSig 函数选择器
     * @param enabled     true = 公开，false = 需要角色
     * @dev 需要 Auth 权限（requiresAuth 修饰符保护）
     */
    function setPublicCapability(address target, bytes4 functionSig, bool enabled) public virtual requiresAuth {
        // 直接设置布尔值
        isCapabilityPublic[target][functionSig] = enabled;

        emit PublicCapabilityUpdated(target, functionSig, enabled);
    }

    /*
     * @notice 设置某个角色是否有权调用指定函数
     * @param role        角色编号（0~255）
     * @param target      目标合约地址
     * @param functionSig 函数选择器
     * @param enabled     true = 授予权限，false = 撤销权限
     * @dev 通过位运算操作角色位图：
     *      - 授予：用OR 将第 role 位置 1  → bitmap |= (1 << role)
     *      - 撤销：用 AND + NOT 将第 role 位清 0 → bitmap &= ~(1 << role)
     */
    function setRoleCapability(
        uint8 role,
        address target,
        bytes4 functionSig,
        bool enabled
    ) public virtual requiresAuth {
        if (enabled) {
            // 如果是授予权限：
            // 将第 role 位置 1，授予该角色调用权限
            getRolesWithCapability[target][functionSig] |= bytes32(1 << role);
        } else {
            // 如果是撤销权限：
            // 将第 role 位清 0，撤销该角色调用权限
            getRolesWithCapability[target][functionSig] &= ~bytes32(1 << role);
        }

        emit RoleCapabilityUpdated(role, target, functionSig, enabled);
    }

    /*//////////////////////////////////////////////////////////////
                       USER ROLE ASSIGNMENT LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @notice 给用户分配或撤销角色
     * @param user    用户地址
     * @param role    角色编号（0~255）
     * @param enabled true = 分配角色，false = 撤销角色
     * @dev 位运算逻辑与 setRoleCapability 相同：
     *      - 分配：bitmap |= (1 << role)→ 第 role 位置 1
     *      - 撤销：bitmap &= ~(1 << role)  → 第 role 位清 0
     */
    function setUserRole(address user, uint8 role, bool enabled) public virtual requiresAuth {
        if (enabled) {
            // 如果是授予权限：
            // 将用户角色位图的第 role 位置 1
            getUserRoles[user] |= bytes32(1 << role);
        } else {
            // 如果是撤销权限：
            // 将用户角色位图的第 role 位清 0
            getUserRoles[user] &= ~bytes32(1 << role);
        }

        emit UserRoleUpdated(user, role, enabled);
    }
}
