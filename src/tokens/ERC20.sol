// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Modern and gas efficient ERC20 + EIP-2612 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)
/// @author Modified from Uniswap (https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/UniswapV2ERC20.sol)
/// @dev Do not manually set balances without updating totalSupply, as the sum of all user balances must not exceed it.
/*
 * 功能总结：
 * 现代化、gas 高效的 ERC20 代币 + EIP-2612 离线授权（permit）实现
 *
 * 核心功能：
 * - ERC20 标准：transfer、transferFrom、approve、balanceOf、allowance、totalSupply
 * - EIP-2612 permit：通过链下签名授权，省去用户额外的 approve 交易
 * - 内部 _mint / _burn：供子合约继承使用
 *
 * 设计亮点：
 * 1. abstract 合约：不能直接部署，必须由子合约继承并实现具体的铸造/销毁逻辑
 * 2. 所有外部函数标记 virtual：子合约可覆写任意函数（如添加黑名单、暂停等）
 * 3. unchecked 优化：利用"余额总和 <= totalSupply <= MAX"的不变量，跳过不必要的溢出检查
 * 4. 无限授权优化：allowance == type(uint256).max 时不扣减，省一次 SSTORE
 * 5. EIP-2612 permit：内置离线签名授权，支持 meta-transaction
 * 6. 链 ID 缓存：构造时缓存 DOMAIN_SEPARATOR，仅在链 fork 后重新计算
 */
abstract contract ERC20 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 转账事件：从 from 向 to 转移 amount 数量的代币
    // from == address(0) 表示铸造，to == address(0) 表示销毁
    event Transfer(address indexed from, address indexed to, uint256 amount);

    // 授权事件：owner 授权 spender 可使用 amount 数量的代币
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            METADATA STORAGE
    //////////////////////////////////////////////////////////////*/

    // 代币名称，如 "Wrapped Ether"
    string public name;

    // 代币符号，如 "WETH"
    string public symbol;

    // 代币精度（小数位数），如 18 表示 1 token = 1e18 最小单位
    // immutable：部署后不可修改，存储在 bytecode 中而非 storage，读取更省 gas
    uint8 public immutable decimals;

    /*//////////////////////////////////////////////////////////////
                              ERC20 STORAGE
    //////////////////////////////////////////////////////////////*/

    // 代币总供应量
    uint256 public totalSupply;

    // 地址 → 余额
    mapping(address => uint256) public balanceOf;

    // owner → spender → 授权额度
    mapping(address => mapping(address => uint256)) public allowance;

    /*//////////////////////////////////////////////////////////////
                            EIP-2612 STORAGE
    //////////////////////////////////////////////////////////////*/

    // 部署时的链 ID，用于检测链是否发生 fork
    uint256 internal immutable INITIAL_CHAIN_ID;

    // 部署时计算的 EIP-712 域分隔符，缓存以避免每次 permit 都重新计算
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    // 地址 → nonce，每次 permit 调用后 +1，防止签名重放攻击
    mapping(address => uint256) public nonces;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 构造函数：初始化代币元数据和 EIP-2612 域分隔符
     * @param _name 代币名称
     * @param _symbol 代币符号
     * @param _decimals 代币精度
     */
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        // 缓存部署时的链 ID 和域分隔符
        // 后续 permit 调用时对比 block.chainid，如果链 fork 了就重新计算
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                               ERC20 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 授权：允许 spender 从 msg.sender 的余额中使用最多 amount 数量的代币
     * 注意：每次调用会覆盖之前的授权额度（不是累加）
     * @param spender 被授权地址
     * @param amount 授权额度
     * @return 始终返回 true（符合 ERC20 规范）
     */
    function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;
    }

    /*
     * @dev 转账：从 msg.sender 向 to 转移 amount 数量的代币
     * @param to 接收地址
     * @param amount 转账数量
     * @return 始终返回 true（符合 ERC20 规范）
     */
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        // 扣减发送方余额（Solidity 0.8 默认溢出检查：余额不足会 revert）
        balanceOf[msg.sender] -= amount;

        // 增加接收方余额
        // 不会溢出：所有用户余额之和 == totalSupply <= type(uint256).max
        // 既然已经从 msg.sender 扣了 amount，totalSupply 不变，to 的余额加 amount 不可能溢出
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(msg.sender, to, amount);

        return true;
    }

    /*
     * @dev 授权转账：从 from 向 to 转移 amount 数量的代币（需要 from 事先授权 msg.sender）
     * @param from 发送地址（代币持有者）
     * @param to 接收地址
     * @param amount 转账数量
     * @return 始终返回 true（符合 ERC20 规范）
     */
    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        // 读取授权额度到局部变量，省 gas（避免多次 SLOAD）
        uint256 allowed = allowance[from][msg.sender];

        // 无限授权优化：如果 allowance == MAX，不扣减授权额度
        // 省一次 SSTORE（该 slot 已被 SLOAD warm 过，写入花费 2900 gas），DeFi 中常见的 "infinite approval" 模式
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

        // 扣减发送方余额（余额不足会 revert）
        balanceOf[from] -= amount;

        // 增加接收方余额（理由同 transfer：不会溢出）
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                             EIP-2612 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev EIP-2612 permit：通过链下签名授权，无需 owner 发送 approve 交易
     *
     * 工作流程：
     * 1. owner 在链下用私钥签名一条授权消息（包含 spender、value、nonce、deadline）
     * 2. 任何人（通常是 spender 或 relayer）调用 permit，提交签名参数 (v, r, s)
     * 3. 合约通过 ecrecover 恢复签名者地址，验证是否与 owner 匹配
     * 4. 验证通过后设置 allowance，效果等同于 owner 调用了 approve
     *
     * 优势：用户只需签名（免费），由协议/relayer 代为提交交易（付 gas）
     *
     * @param owner 代币持有者（授权方）
     * @param spender 被授权地址
     * @param value 授权额度
     * @param deadline 签名过期时间（Unix 时间戳），过期后签名无效
     * @param v ECDSA 签名参数（恢复标识符）
     * @param r ECDSA 签名参数
     * @param s ECDSA 签名参数
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        // 检查签名是否过期
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");

        // unchecked：唯一的数学运算是 nonces[owner]++，uint256 不可能在现实中溢出
        unchecked {
            /*
             * 签名结构（EIP-191 + EIP-712）：
             *   signedData = 0x19 0x01 + domainSeparator + structHash
             *   - 0x19：EIP-191 前缀，标识这不是一笔普通交易（交易的 RLP 编码不会以 0x19 开头）
             *     如果没有该前缀，攻击者可以：
             *       1. 精心构造一条"消息"，使 keccak256(消息) == 某笔转账交易的 txHash
             *       2. 用户以为在签一条普通消息（如 permit 授权）
             *       3. 实际签出的 (v, r, s) 对那笔转账交易也有效
             *       4. 攻击者拿到签名，广播那笔交易，资金被盗
             *     加了 0x19 前缀后，消息哈希永远不可能等于任何合法交易的 txHash
             *   - 0x01：EIP-191 版本号，表示后续数据是 EIP-712 结构化数据
             *     注：EIP-191 共定义了 3 个版本：
             *       0x00 — 验证者地址模式：0x19 0x00 + <验证者合约地址(20字节)> + <data>，用于多签钱包等场景
             *       0x01 — EIP-712 结构化数据：0x19 0x01 + domainSeparator + structHash（本合约使用）
             *       0x45 — personal_sign：0x45 是字符 'E' 的 ASCII 码，
             *              实际前缀为 "\x19Ethereum Signed Message:\n<长度>" + <消息>，
             *              即 MetaMask 弹窗签名时使用的格式
             *   - domainSeparator：签名的作用域（绑定到哪个合约、哪条链）
             *   - structHash：签名的内容（Permit 的具体参数）
             *
             * 使用 ecrecover 从签名中恢复签名者地址，验证是否与 owner 匹配
             */
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        // EIP-191 前缀（详见上方注释）
                        "\x19\x01",
                        // 域分隔符：绑定到特定合约、链、版本，防止跨合约/跨链重放
                        DOMAIN_SEPARATOR(),
                        // 结构化数据的哈希：Permit 类型的具体参数
                        keccak256(
                            abi.encode(
                                // Permit 类型哈希（EIP-712 typeHash）
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                // 读取并递增 nonce：防止同一签名被重复使用（重放攻击）
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            // 验证恢复的地址：
            // 1. 不能是 address(0)（ecrecover 在签名无效时返回 0）
            // 2. 必须等于 owner（确认是 owner 本人签的）
            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");

            // 设置授权额度（等同于 owner 调用 approve(spender, value)）
            allowance[recoveredAddress][spender] = value;
        }

        emit Approval(owner, spender, value);
    }

    /*
     * @dev 获取当前的 EIP-712 域分隔符
     * 如果链 ID 未变（未 fork），直接返回缓存值，省 gas
     * 如果链 fork 了（block.chainid != INITIAL_CHAIN_ID），重新计算
     * 这防止了 fork 后签名在两条链上都有效的重放攻击
     * @return EIP-712 域分隔符
     */
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }

    /*
     * @dev 计算 EIP-712 域分隔符（Domain Separator）
     *
     * 什么是域分隔符？
     *   EIP-712 签名由两层组成：签名 = sign(domainSeparator + structHash)
     *   - structHash 定义签名的"内容"（具体要执行什么操作、带哪些参数）
     *   - domainSeparator 定义签名的"作用域"（在哪个合约、哪条链上有效）
     *   两个不同合约可以有相同的 structHash，但域分隔符不同，签名互不通用
     *
     * EIP-712 编码规则：
     *   1. typeHash 定义了什么字段，abi.encode 就按顺序跟什么字段，一一对应
     *   2. 动态类型（string、bytes）要先取 keccak256，值类型（uint256、address 等）直接放
     *   例：typeHash 中有 "string name"，encode 时要放 keccak256(bytes(name)) 而不是 name 本身
     *
     * 域分隔符的字段不是固定的，EIP-712 定义了 5 个可选字段：name、version、chainId、verifyingContract、salt
     * 开发者根据需要选择使用哪些。本合约用了前 4 个（最常见的组合）
     *
     * 域分隔符 = keccak256(abi.encode(typeHash, nameHash, versionHash, chainId, contractAddress))
     * 将签名绑定到：特定合约名称 + 版本 "1" + 当前链 ID + 合约地址
     * 任何一项不匹配，签名验证都会失败
     * @return EIP-712 域分隔符
     */
    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    // EIP-712 域类型哈希
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    // 合约/协议名称的哈希
                    // name 填人类可读的名称即可（如 "USD Coin"、"Aave V3"、"ENS"），无格式限制
                    // 作用：让用户在钱包签名弹窗中看到自己在跟哪个合约交互
                    // 本合约直接复用构造函数传入的代币 name
                    keccak256(bytes(name)),
                    // 版本号的哈希，固定为 "1"
                    keccak256("1"),
                    // 当前链 ID
                    block.chainid,
                    // 当前合约地址
                    address(this)
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 内部铸造函数：创建 amount 数量的代币并分配给 to
     * 只能由子合约调用（internal），子合约负责添加访问控制（如 onlyOwner）
     * @param to 接收新铸造代币的地址
     * @param amount 铸造数量
     */
    function _mint(address to, uint256 amount) internal virtual {
        // 增加总供应量（溢出会 revert，防止无限铸造）
        totalSupply += amount;

        // 增加接收方余额
        // 不会溢出：balanceOf[to] <= totalSupply（上面已检查不溢出），所以 balanceOf[to] + amount <= 新的 totalSupply
        unchecked {
            balanceOf[to] += amount;
        }

        // 按 ERC20 规范，铸造 = 从 address(0) 转入
        emit Transfer(address(0), to, amount);
    }

    /*
     * @dev 内部销毁函数：销毁 from 持有的 amount 数量的代币
     * 只能由子合约调用（internal），子合约负责添加访问控制
     * @param from 被销毁代币的持有地址
     * @param amount 销毁数量
     */
    function _burn(address from, uint256 amount) internal virtual {
        // 扣减持有者余额（余额不足会 revert）
        balanceOf[from] -= amount;

        // 减少总供应量
        // 不会下溢：totalSupply >= balanceOf[from]（上面已扣减成功），
        // 所以 totalSupply >= amount
        unchecked {
            totalSupply -= amount;
        }

        // 按 ERC20 规范，销毁 = 转给 address(0)
        emit Transfer(from, address(0), amount);
    }
}
