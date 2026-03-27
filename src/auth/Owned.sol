// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Simple single owner authorization mixin.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol)
/*
 * 功能总结：
 * 极简的单所有者权限控制抽象合约。
 * - 维护一个 owner 状态变量，提供 onlyOwner 修饰符用于函数访问控制
 * - 支持通过 transferOwnership() 一步转移所有权（无零地址校验、无两步确认）
 * - 所有核心函数和修饰符均为 virtual，允许子合约灵活重写
 */
abstract contract Owned {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /** @dev 所有权转移事件
     * @param user     原所有者地址（首次部署时为 address(0)）
     * @param newOwner 新所有者地址
     */
    event OwnershipTransferred(address indexed user, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP STORAGE
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 当前合约所有者地址，public 自动生成 getter
     *是所有权限判断的唯一依据
     */
    address public owner;

    /** @dev 仅允许当前 owner 调用的访问控制修饰符
     *      若msg.sender != owner，则 revert 并返回 "UNAUTHORIZED"
     *      标记为 virtual，子合约可 override 以自定义权限逻辑（如多签、角色分级等）
     */
    modifier onlyOwner() virtual {
        require(msg.sender == owner, "UNAUTHORIZED");

        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 构造函数，部署时设置初始所有者
     * @param _owner 初始所有者地址
     *      - 不做零地址校验，调用方需自行确保传入有效地址
     *      - 触发 OwnershipTransferred(address(0), _owner) 事件，表示从"无主"状态转为_owner
     */
    constructor(address _owner) {
        owner = _owner;

        emit OwnershipTransferred(address(0), _owner);
    }

    /*//////////////////////////////////////////////////////////////
                             OWNERSHIP LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 一步转移所有权，将owner 直接更新为 newOwner
     * @param newOwner 新所有者地址
     *      - 仅当前owner 可调用（onlyOwner 修饰符）
     *      - 不做零地址校验：可传入 address(0) 以放弃所有权（不可逆）
     *      - 无两步确认机制：一旦调用立即生效，误操作无法恢复
     *      - 标记为 virtual，子合约可 override 添加额外校验（如禁止转给零地址、增加两步确认等）
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        owner = newOwner;

        emit OwnershipTransferred(msg.sender, newOwner);
    }
}
