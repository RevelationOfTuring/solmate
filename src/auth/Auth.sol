// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Provides a flexible and updatable auth pattern which is completely separate from application logic.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Auth.sol)
/// @author Modified from Dappsys (https://github.com/dapphub/ds-auth/blob/master/src/auth.sol)

/*
 * 功能总结：
 * 灵活且可升级的权限控制抽象合约，将授权逻辑与业务逻辑完全解耦。
 * - 支持双重授权机制：owner 直接权限 + Authority 外部合约委托权限
 * - Authority 是一个外部授权策略接口，可实现基于角色（RBAC）、白名单等任意策略
 * - owner 可一步转移所有权，也可随时更换 Authority 合约
 * - isAuthorized 中优先查询 Authority，再判断 owner，节省大部分场景的 gas
 * - 所有核心函数和修饰符均为 virtual，子合约可灵活重写
 *
 * ┌────────────────────────────────────────┐
 * │       RoleAuthority（权限注册表）        │
 * │                                        │
 * │ 记录：谁 → 对哪个合约 → 哪个函数 → 能否调用  │
 * └──────────┬────────────┬────────── ─────┘
 *      canCall 查询    canCall 查询
 *            │            │
 *            ▼            ▼
 *      ┌──────────┐  ┌──────────┐
 *      │ 合约 A    │  │ 合约 B   │
 *      │ is Auth  │  │ is Auth  │
 *      │          │  │          │
 *      │ mint()   │  │ pause()  │
 *      │ burn()   │  │ upgrade()│
 *      └──────────┘  └──────────┘
 */
abstract contract Auth {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 所有权转移事件
     * @param user     原所有者地址（首次部署时为 msg.sender / 部署者）
     * @param newOwner 新所有者地址
     */
    event OwnershipTransferred(address indexed user, address indexed newOwner);

    /*
     * @dev Authority 授权合约更新事件
     * @param user         触发更新的调用者地址
     * @param newAuthority 新的 Authority 合约地址
     */
    event AuthorityUpdated(address indexed user, Authority indexed newAuthority);

    /*//////////////////////////////////////////////////////////////
                            AUTH STORAGE
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 当前合约所有者地址，public 自动生成 getter
     *      拥有最高权限，是 isAuthorized 判断的兜底条件
     */
    address public owner;

    /*
     * @dev 外部授权策略合约，public 自动生成 getter
     *      实现 Authority 接口的 canCall()，可为任意自定义权限逻辑
     *      设置为 address(0) 时表示不使用外部授权，仅依赖 owner
     */
    Authority public authority;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 构造函数，部署时设置初始 owner 和 Authority
     * @param _owner     初始所有者地址
     * @param _authority 初始授权策略合约地址（可传 Authority(address(0)) 表示不启用）
     *      - 不做零地址校验，调用方需自行确保传入有效地址
     *      - 分别触发 OwnershipTransferred 和 AuthorityUpdated 事件
     */
    constructor(address _owner, Authority _authority) {
        owner = _owner;
        authority = _authority;

        emit OwnershipTransferred(msg.sender, _owner);
        emit AuthorityUpdated(msg.sender, _authority);
    }

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 权限校验修饰符，要求调用者通过 isAuthorized 检查
     *      结合 msg.sender（调用者）和 msg.sig（函数选择器）进行双重验证
     *      若未授权，revert 并返回 "UNAUTHORIZED"
     *      标记为 virtual，子合约可 override 自定义权限逻辑
     */
    modifier requiresAuth() virtual {
        require(isAuthorized(msg.sender, msg.sig), "UNAUTHORIZED");

        _;
    }

    /*//////////////////////////////////////////////////////////////
                            AUTH LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 核心授权判断函数，判断 user 是否有权调用本合约的指定函数
     * @param user        待检查的调用者地址
     * @param functionSig 待检查的函数选择器（bytes4）
     * @return bool       是否授权通过
     *
     * 判断优先级：
     *   1. 先检查 Authority 合约（若address非零则调用 canCall）
     *   2. 再检查是否为 owner
     * 这样设计在大多数场景下更省gas，但注意：
     *   如果 Authority 合约异常（revert /消耗大量 gas），即使是 owner 也无法调用受保护函数
     *
     * gas 优化：将 authority缓存到局部变量 auth，避免多次 warm SLOAD（节省约 100 gas）
     */
    function isAuthorized(address user, bytes4 functionSig) internal view virtual returns (bool) {
        Authority auth = authority; // Memoizing authority saves us a warm SLOAD, around 100 gas.

        // Checking if the caller is the owner only after calling the authority saves gas in most cases, but be
        // aware that this makes protected functions uncallable even to the owner if the authority is out of order.
        return (address(auth) != address(0) && auth.canCall(user, address(this), functionSig)) || user == owner;
    }

    /*
     * @dev 更换 Authority 授权策略合约
     * @param newAuthority 新的 Authority 合约地址（可传 Authority(address(0)) 以禁用外部授权）
     *
     * 权限控制：
     *   - 优先检查 msg.sender == owner（确保 owner 始终能更换 Authority）
     *   - 其次通过当前 authority.canCall 检查（允许被授权的第三方更换）
     *   - 之所以先判断 owner 而非用 requiresAuth 修饰符，是为了防止 Authority 合约
     *     异常（revert / 消耗大量 gas）时 owner 也无法更换的死锁情况
     *
     * 注意：不做零地址校验，传入 address(0) 将清除外部授权
     */
    function setAuthority(Authority newAuthority) public virtual {
        // We check if the caller is the owner first because we want to ensure they can
        // always swap out the authority even if it's reverting or using up a lot of gas.
        require(msg.sender == owner || authority.canCall(msg.sender, address(this), msg.sig));

        authority = newAuthority;

        emit AuthorityUpdated(msg.sender, newAuthority);
    }

    /*
     * @dev 一步转移所有权，将 owner 直接更新为 newOwner
     * @param newOwner 新所有者地址
     *      - 使用 requiresAuth 修饰符：owner 或 Authority 授权的地址均可调用
     *      - 不做零地址校验：可传入 address(0) 以放弃所有权（不可逆）
     *      - 无两步确认机制：一旦调用立即生效，误操作无法恢复
     *      - 标记为 virtual，子合约可 override 添加额外校验
     */
    function transferOwnership(address newOwner) public virtual requiresAuth {
        // 直接覆盖 owner（无旧值校验、无零地址校验）
        owner = newOwner;

        // 触发事件，记录谁转移了所有权以及新 owner 地址
        emit OwnershipTransferred(msg.sender, newOwner);
    }
}

/// @notice A generic interface for a contract which provides authorization data to an Auth instance.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Auth.sol)
/// @author Modified from Dappsys (https://github.com/dapphub/ds-auth/blob/master/src/auth.sol)
/*
 * 功能总结：
 * 通用授权策略接口，为 Auth 合约提供外部权限判断能力。
 * - 任何实现此接口的合约都可作为 Auth 的授权后端
 * - 可实现 RBAC、白名单、时间锁、多签等任意授权策略
 */
interface Authority {
    /*
     * @dev 判断指定用户是否有权对目标合约调用指定函数
     * @param user        待检查的调用者地址（往往是msg.sender）
     * @param target      被调用的目标合约地址（即 Auth 合约自身）
     * @param functionSig 被调用函数的选择器（前 4 字节）
     * @return bool       true 表示授权通过，false 表示拒绝
     */
    function canCall(address user, address target, bytes4 functionSig) external view returns (bool);
}
