// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Minimalist and gas efficient standard ERC6909 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC6909.sol)
/*
 * 功能总结：
 * 极简、gas 高效的 ERC-6909 最小多代币接口实现
 *
 * 核心功能：
 * - 多代币管理：transfer、transferFrom、approve、balanceOf、allowance（均按 id 区分）
 * - 全局操作员：setOperator / isOperator，授权后可代操作所有 id 的代币
 * - ERC165 接口检测：supportsInterface
 * - 内部 _mint / _burn：供子合约继承使用
 *
 * 与 ERC1155 的关键区别：
 * 1. 更轻量：去掉了 batch 操作、safe 回调（onERC6909Received）、uri
 * 2. 新增按 id 的精细授权（approve + allowance）——ERC1155 只有全局授权，没有按 id 的 approve
 *    全局操作员（setOperator）与 ERC1155 的 setApprovalForAll 功能相同，都不按 id 隔离
 * 3. transfer 不是 safe 的：不调用接收方的回调，类似 ERC20 的 transfer
 * 4. 无限授权优化：allowance == type(uint256).max 时不扣减，省一次 SSTORE（与 ERC20 一致）
 * 5. Transfer 事件多一个 caller 字段：区分实际调用者和代币持有者
 * 总结：当你的合约是"多币种账本"，且不需要 ERC1155 的 batch/safe/uri 时，ERC6909 就是最佳选择
 *
 * 典型使用场景：
 * 1. Uniswap v4 内部记账：Singleton PoolManager 用 ERC6909 作为内部余额凭证，
 *    用户存入 ERC20 后获得 ERC6909 余额，后续 swap/加减流动性只更新同合约内的
 *    mapping 余额，无需反复跨合约调用 ERC20 transfer，最终提取时才做一次外部转账。
 *    为什么不用裸 mapping？
 *    答：ERC6909 是标准代币接口——余额可转让（transfer/approve），
 *      其他协议（借贷、DEX）可直接识别和集成，钱包和浏览器可通过标准事件展示持仓。
 *      裸 mapping 是私有账本，ERC6909 是公开的、可组合的、可转让的标准账本
 * 2. 金融衍生品（期权/期货）：一个合约管理多个到期日/行权价的仓位，
 *    每个 id 代表一种合约规格，approve 可按 id 精细授权给清算机器人
 * 3. 多币种账本/支付通道：多种代币的内部流转只改余额不做外部转账，
 *    结算时才批量提取，类似 CEX 的内部账本模式
 *
 * 典型模式（id 代表什么）：
 * - 外部资产凭证：id = ERC20 地址 → uint256，用于多币种金库、DEX 内部记账（如 Uniswap v4）
 * - 合约内生代币：id = 业务编号（到期日、行权价等），用于期权/期货、多期限债券
 * - 资金池份额：id = 池子编号，用于多池聚合器、借贷协议
 */
abstract contract ERC6909 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 操作员授权事件：owner 将 operator 的全局操作权限设为 approved
    // approved = true 表示授权，false 表示撤销
    event OperatorSet(address indexed owner, address indexed operator, bool approved);

    // 按 id 授权事件：owner 授权 spender 可使用 id 代币 amount 数量
    // 注意 id 是 indexed 的，方便按代币类型过滤事件
    event Approval(address indexed owner, address indexed spender, uint256 indexed id, uint256 amount);

    // 转移事件：caller 将 amount 个 id 代币从 from 转给 to
    // caller 是实际调用者（msg.sender），from 是代币持有者
    // caller == from 表示自主转移，caller != from 表示代理转移（operator 或 approved spender）
    // 注意：caller 没有 indexed（与 ERC1155 的 operator indexed 不同）
    event Transfer(address caller, address indexed from, address indexed to, uint256 indexed id, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             ERC6909 STORAGE
    //////////////////////////////////////////////////////////////*/

    // 全局操作员映射：owner → operator → 是否授权
    // 被授权的 operator 可以代操作 owner 所有 id 的代币（类似 ERC1155 的 setApprovalForAll）
    mapping(address => mapping(address => bool)) public isOperator;

    // 余额映射：owner → id → 余额
    // 与 ERC1155 结构完全相同
    mapping(address => mapping(uint256 => uint256)) public balanceOf;

    // 按 id 授权映射：owner → spender → id → 授权额度
    // 三层嵌套 mapping，这是 ERC6909 独有的——ERC1155 没有按 id 的 approve
    mapping(address => mapping(address => mapping(uint256 => uint256))) public allowance;

    /*//////////////////////////////////////////////////////////////
                              ERC6909 LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 自主转移：msg.sender 将自己的 id 代币转给 receiver
     * @dev 不调用接收方回调（非 safe），余额不足时自动 underflow revert
     * @param receiver 接收代币的地址
     * @param id       代币类型 ID
     * @param amount   转移数量
     * @return         是否成功（始终 true，失败则 revert）
     */
    function transfer(address receiver, uint256 id, uint256 amount) public virtual returns (bool) {
        // 扣减发送方余额（不足则 underflow revert）
        balanceOf[msg.sender][id] -= amount;

        // 增加接收方余额
        // 与 ERC20/ERC1155 的 solmate 实现不同，此处没有用 unchecked，
        // 因为 ERC6909 没有 totalSupply 跟踪，无法保证"余额总和不溢出"的不变量
        balanceOf[receiver][id] += amount;

        // caller 和 from 都是 msg.sender（自主转移）
        emit Transfer(msg.sender, msg.sender, receiver, id, amount);

        return true;
    }

    /**
     * @notice 代理转移：从 sender 账户转出 id 代币给 receiver
     * @dev 权限检查优先级：自己 > operator > allowance
     *      三种情况可跳过 allowance 扣减：
     *      1. msg.sender == sender（自己操作自己的代币）
     *      2. isOperator[sender][msg.sender]（全局操作员）
     *      3. allowance == type(uint256).max（无限授权，不扣减，省一次 SSTORE）
     * @param sender   代币持有者
     * @param receiver 接收代币的地址
     * @param id       代币类型 ID
     * @param amount   转移数量
     * @return         是否成功（始终 true，失败则 revert）
     */
    function transferFrom(address sender, address receiver, uint256 id, uint256 amount) public virtual returns (bool) {
        // 只有既不是本人、也不是 operator 时，才走 allowance 逻辑
        if (msg.sender != sender && !isOperator[sender][msg.sender]) {
            uint256 allowed = allowance[sender][msg.sender][id];
            // 无限授权优化：type(uint256).max 不扣减，省一次 SSTORE（与 ERC20 一致）
            if (allowed != type(uint256).max) allowance[sender][msg.sender][id] = allowed - amount;
        }

        // 扣减 sender 余额
        balanceOf[sender][id] -= amount;

        // 增加 receiver 余额
        balanceOf[receiver][id] += amount;

        // caller 是 msg.sender，from 是 sender（两者可能不同）
        emit Transfer(msg.sender, sender, receiver, id, amount);

        return true;
    }

    /**
     * @notice 按 id 授权：msg.sender 授权 spender 可使用自己 id 代币 amount 数量
     * @dev 覆盖式写入（不是增量），与 ERC20 的 approve 行为一致
     * @param spender 被授权的地址
     * @param id      代币类型 ID
     * @param amount  授权额度
     * @return        是否成功（始终 true）
     */
    function approve(address spender, uint256 id, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender][id] = amount;

        emit Approval(msg.sender, spender, id, amount);

        return true;
    }

    /**
     * @notice 全局操作员授权：msg.sender 将 operator 设为全局操作员（或撤销）
     * @dev 被授权后 operator 可代操作 msg.sender 所有 id 的代币，无需单独 approve
     *      类似 ERC1155 的 setApprovalForAll
     * @param operator 被授权/撤销的操作员地址
     * @param approved true 授权，false 撤销
     * @return         是否成功（始终 true）
     */
    function setOperator(address operator, bool approved) public virtual returns (bool) {
        isOperator[msg.sender][operator] = approved;

        emit OperatorSet(msg.sender, operator, approved);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * ERC165 接口检测：声明本合约支持哪些接口
     * ERC6909 规范要求必须实现此函数
     *
     * 支持的接口：
     * - 0x01ffc9a7：ERC165（supportsInterface()）
     * - 0x0f632fb3：ERC6909（balanceOf()、allowance()、isOperator()、
     *               transfer()、transferFrom()、approve()、setOperator()）
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0x0f632fb3; // ERC165 Interface ID for ERC6909
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 内部铸造：给 receiver 铸造 amount 个 id 代币
     * @dev from == address(0) 表示铸造（凭空创建）
     *      没有 totalSupply 跟踪，子合约如需要应自行维护
     * @param receiver 接收代币的地址
     * @param id       代币类型 ID
     * @param amount   铸造数量
     */
    function _mint(address receiver, uint256 id, uint256 amount) internal virtual {
        balanceOf[receiver][id] += amount;

        emit Transfer(msg.sender, address(0), receiver, id, amount);
    }

    /**
     * @notice 内部销毁：从 sender 销毁 amount 个 id 代币
     * @dev to == address(0) 表示销毁
     *      余额不足时 underflow revert
     * @param sender 被销毁代币的持有者
     * @param id     代币类型 ID
     * @param amount 销毁数量
     */
    function _burn(address sender, uint256 id, uint256 amount) internal virtual {
        balanceOf[sender][id] -= amount;

        emit Transfer(msg.sender, sender, address(0), id, amount);
    }
}
