// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Modern, minimalist, and gas efficient ERC-721 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol)
/*
 * 功能总结：
 * 现代化、极简、gas 高效的 ERC-721 非同质化代币（NFT）实现
 *
 * 核心功能：
 * - ERC721 标准：ownerOf、balanceOf、transferFrom、safeTransferFrom、approve、setApprovalForAll
 * - ERC165 接口检测：supportsInterface
 * - 内部 _mint / _burn / _safeMint：供子合约继承使用
 *
 * 设计亮点：
 * 1. abstract 合约：不能直接部署，必须由子合约继承并实现 tokenURI
 * 2. 所有外部函数标记 virtual：子合约可覆写任意函数（如添加版税、暂停等）
 * 3. unchecked 优化：余额增减在所有权验证后使用 unchecked，省去溢出检查
 * 4. transferFrom 自动清除单个授权：转移后 delete getApproved[id]，防止旧授权残留
 * 5. safeTransferFrom 安全检查：如果接收方是合约，调用 onERC721Received 确认其能处理 NFT
 * 6. 无 enumerable 扩展：不跟踪 token 列表和索引，极致精简，降低 mint/transfer 的 gas 成本
 *
 * 与 ERC20 的关键区别：
 * - ERC20：同质化，amount 数量转移，一个 approve 管所有代币
 * - ERC721：非同质化，每个 token 有唯一 id，approve 分为单个（approve）和全局（setApprovalForAll）
 * - ERC721 多了 safeTransferFrom 和 ERC165 支持
 */
abstract contract ERC721 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 转移事件：NFT id 从 from 转给 to
    // from == address(0) 表示铸造，to == address(0) 表示销毁
    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    // 单个授权事件：owner 授权 spender 可操作 NFT id
    // 每个 NFT 同一时间只能有一个被授权地址（新授权覆盖旧授权）
    event Approval(address indexed owner, address indexed spender, uint256 indexed id);

    // 全局授权事件：owner 将所有 NFT 的操作权授予/撤销 operator
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /*//////////////////////////////////////////////////////////////
                         METADATA STORAGE/LOGIC
    //////////////////////////////////////////////////////////////*/

    // NFT 集合名称，如 "Bored Ape Yacht Club"
    string public name;

    // NFT 集合符号，如 "BAYC"
    string public symbol;

    // 返回指定 NFT 的元数据 URI（如 IPFS 链接），子合约必须实现
    function tokenURI(uint256 id) public view virtual returns (string memory);

    /*//////////////////////////////////////////////////////////////
                      ERC721 BALANCE/OWNER STORAGE
    //////////////////////////////////////////////////////////////*/

    // token id → 所有者地址（address(0) 表示未铸造）
    mapping(uint256 => address) internal _ownerOf;

    // 地址 → 持有的 NFT 数量
    mapping(address => uint256) internal _balanceOf;

    /*
     * @dev 查询 NFT 的所有者
     * @param id NFT 的 token id
     * @return owner NFT 的所有者地址，未铸造则 revert
     */
    function ownerOf(uint256 id) public view virtual returns (address owner) {
        // Solidity 技巧：在 require 的条件表达式中同时完成赋值和检查
        // (owner = _ownerOf[id]) != address(0) 先将 _ownerOf[id] 赋给返回变量 owner，再检查非零
        // 等价于：owner = _ownerOf[id]; require(owner != address(0))，但更紧凑
        require((owner = _ownerOf[id]) != address(0), "NOT_MINTED");
    }

    /*
     * @dev 查询地址持有的 NFT 数量
     *      禁止查询零地址（ERC721 规范要求）
     * @param owner 要查询的地址
     * @return 持有的 NFT 数量
     */
    function balanceOf(address owner) public view virtual returns (uint256) {
        require(owner != address(0), "ZERO_ADDRESS");

        return _balanceOf[owner];
    }

    /*//////////////////////////////////////////////////////////////
                         ERC721 APPROVAL STORAGE
    //////////////////////////////////////////////////////////////*/

    // token id → 被授权的地址（每个 NFT 只能有一个被授权者）
    // 与 ERC20 的 allowance 不同：ERC20 是 owner → spender → amount（金额授权）
    // ERC721 是 id → spender（单个 NFT 的操作权）
    mapping(uint256 => address) public getApproved;

    // owner → operator → 是否授权（全局授权：operator 可操作 owner 的所有 NFT）
    // 类似 ERC20 的"无限授权"，但粒度是整个集合而非金额
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 构造函数：初始化 NFT 集合的元数据
     *      与 ERC20 构造函数相比少了 decimals（NFT 不可分割，没有小数位概念）
     * @param _name 集合名称
     * @param _symbol 集合符号
     */
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    /*//////////////////////////////////////////////////////////////
                              ERC721 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 单个授权：授权 spender 可以转移指定的 NFT
     *      只有 NFT 的 owner 或已被全局授权的 operator 才能调用
     *      每次调用会覆盖该 NFT 之前的授权（同一时间只有一个被授权者）
     *      注意：与 ERC20 不同，approve 没有返回值
     * @param spender 被授权地址
     * @param id NFT 的 token id
     */
    function approve(address spender, uint256 id) public virtual {
        address owner = _ownerOf[id];

        // 权限检查：调用者必须是 owner 本人，或已被 owner 全局授权的 operator
        require(msg.sender == owner || isApprovedForAll[owner][msg.sender], "NOT_AUTHORIZED");

        getApproved[id] = spender;

        emit Approval(owner, spender, id);
    }

    /*
     * @dev 全局授权/撤销：授权或撤销 operator 对 msg.sender 所有 NFT 的操作权
     *      approved = true 时授权，false 时撤销
     *      常见用途：用户授权 NFT 市场（如 OpenSea）代为转移自己的所有 NFT
     * @param operator 被授权的操作者地址
     * @param approved 是否授权
     */
    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;

        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /*
     * @dev 转移 NFT：从 from 转移 token id 到 to
     *      调用者必须是 from 本人、被全局授权的 operator、或被单独授权的 spender
     *      转移后自动清除该 NFT 的单个授权（防止旧授权残留给新 owner 带来风险）
     *      注意：不检查 to 是否能接收 NFT（合约地址可能无法处理），安全版本请用 safeTransferFrom
     * @param from 当前 owner
     * @param to 接收地址
     * @param id NFT 的 token id
     */
    function transferFrom(address from, address to, uint256 id) public virtual {
        // 验证 from 确实是该 NFT 的 owner
        require(from == _ownerOf[id], "WRONG_FROM");

        // 禁止转移到零地址（零地址代表"不存在"，转入等于销毁但不触发正确的销毁逻辑）
        require(to != address(0), "INVALID_RECIPIENT");

        // 权限检查（三选一）：
        // 1. msg.sender == from（owner 本人）
        // 2. isApprovedForAll[from][msg.sender]（全局授权的 operator）
        // 3. msg.sender == getApproved[id]（该 NFT 的单独被授权者）
        require(
            msg.sender == from || isApprovedForAll[from][msg.sender] || msg.sender == getApproved[id],
            "NOT_AUTHORIZED"
        );

        // 更新余额
        // unchecked 安全理由：
        // - from 的余额不会下溢：上面已验证 from 是 owner，至少持有 1 个 NFT
        // - to 的余额不会溢出：地址总数有限，单个地址不可能持有接近 2^256 个 NFT
        unchecked {
            _balanceOf[from]--;

            _balanceOf[to]++;
        }

        // 转移所有权
        _ownerOf[id] = to;

        // 清除旧的单个授权
        // 使用 delete 将映射值重置为零，会触发 SSTORE gas 退款（如果原值非零）
        delete getApproved[id];

        emit Transfer(from, to, id);
    }

    /*
     * @dev 安全转移（无附加数据）：先调用 transferFrom 转移，再检查接收方是否能处理 NFT
     *      安全检查逻辑：
     *      - 如果 to 是 EOA（to.code.length == 0）：无需检查，EOA 总能"持有" NFT
     *      - 如果 to 是合约：调用 to.onERC721Received()，要求返回正确的 selector
     *        如果合约没有实现该接口或返回错误值，则 revert
     *      这防止了 NFT 被永久锁死在不支持 ERC721 的合约中
     * @param from 当前 owner
     * @param to 接收地址
     * @param id NFT 的 token id
     */
    function safeTransferFrom(address from, address to, uint256 id) public virtual {
        transferFrom(from, to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, from, id, "") ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    /*
     * @dev 安全转移（带附加数据）：与上面的 safeTransferFrom 相同，但额外传递 data 给接收方合约
     *      data 会原样传入 onERC721Received()，接收方合约可据此执行自定义逻辑
     *      典型用途：在转移的同时传递操作指令（如"转入并质押"）
     * @param from 当前 owner
     * @param to 接收地址
     * @param id NFT 的 token id
     * @param data 传递给接收方的附加数据
     */
    function safeTransferFrom(address from, address to, uint256 id, bytes calldata data) public virtual {
        transferFrom(from, to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, from, id, data) ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev ERC165 接口检测：声明本合约支持哪些接口
     *      ERC721 规范要求必须实现此函数
     *      返回 true 的接口：
     *      - 0x01ffc9a7：ERC165（supportsInterface()）
     *      - 0x80ac58cd：ERC721（balanceOf()、ownerOf()、transferFrom()、approve()、setApprovalForAll()、safeTransferFrom()）
     *      - 0x5b5e139f：ERC721Metadata（name()、symbol()、tokenURI()）
     *      注意：未声明 ERC721Enumerable（0x780e9d63），因为 solmate 不实现 enumerable 功能
     * @param interfaceId 要查询的接口 ID（4 字节）
     * @return 是否支持该接口
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0x80ac58cd || // ERC165 Interface ID for ERC721
            interfaceId == 0x5b5e139f; // ERC165 Interface ID for ERC721Metadata
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 内部铸造：创建新的 NFT 并分配给 to
     *      internal virtual：只能被子合约调用，且可被覆写
     *      子合约通常会包装成 public mint() 并添加权限控制、价格检查等逻辑
     * @param to 接收地址（不能为零地址）
     * @param id 要铸造的 token id（不能已存在）
     */
    function _mint(address to, uint256 id) internal virtual {
        // 禁止铸造到零地址
        require(to != address(0), "INVALID_RECIPIENT");

        // 禁止重复铸造同一个 id
        require(_ownerOf[id] == address(0), "ALREADY_MINTED");

        // 增加接收方余额
        // unchecked 安全理由：单个地址不可能铸造接近 2^256 个 NFT，溢出不现实
        unchecked {
            _balanceOf[to]++;
        }

        _ownerOf[id] = to;

        // from = address(0) 表示铸造
        emit Transfer(address(0), to, id);
    }

    /*
     * @dev 内部销毁：销毁指定的 NFT
     *      注意：与 ERC20._burn 不同，这里只需要 id（不需要显式传入 owner 参数），从 _ownerOf 自动查 owner
     *      同时清除该 NFT 的单个授权
     * @param id 要销毁的 token id（必须已存在）
     */
    function _burn(uint256 id) internal virtual {
        address owner = _ownerOf[id];

        // 检查 NFT 存在（owner 不为零地址）
        require(owner != address(0), "NOT_MINTED");

        // 减少 owner 的余额
        // unchecked 安全理由：上面已确认 owner 持有该 NFT，余额至少为 1，不会下溢
        unchecked {
            _balanceOf[owner]--;
        }

        // 删除所有权记录
        delete _ownerOf[id];

        // 清除单个授权
        delete getApproved[id];

        // to = address(0) 表示销毁
        emit Transfer(owner, address(0), id);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL SAFE MINT LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 安全铸造（无附加数据）：先铸造，再检查接收方是否能处理 NFT
     *      逻辑同 safeTransferFrom 的安全检查，区别是 from 传入 address(0)（表示铸造）
     * @param to 接收地址
     * @param id 要铸造的 token id
     */
    function _safeMint(address to, uint256 id) internal virtual {
        _mint(to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, address(0), id, "") ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    /*
     * @dev 安全铸造（带附加数据）：先铸造，再检查接收方并传递 data
     * @param to 接收地址
     * @param id 要铸造的 token id
     * @param data 传递给接收方的附加数据
     */
    function _safeMint(address to, uint256 id, bytes memory data) internal virtual {
        _mint(to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, address(0), id, data) ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }
}

/// @notice A generic interface for a contract which properly accepts ERC721 tokens.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol)
/*
 * ERC721 代币接收器接口
 * 任何想通过 safeTransferFrom / _safeMint 接收 NFT 的合约都必须实现此接口
 * 默认实现直接返回正确的 selector，表示"我接受 NFT"
 * 子合约可覆写 onERC721Received 添加自定义验证逻辑（如只接受特定集合的 NFT）
 */
abstract contract ERC721TokenReceiver {
    /*
     * @dev 当合约通过 safeTransferFrom / _safeMint 收到 NFT 时被调用
     *      必须返回 onERC721Received.selector（即 0x150b7a02）才能成功接收
     *      data 由调用方传入，接收方可解码后执行自定义逻辑，
     *      实现"转移/铸造 + 后续操作"一笔交易完成
     *      典型用途：铸造并质押（data 编码 poolId）、转入并挂单（data 编码价格）等
     * @param operator 触发转移的调用者（msg.sender）
     * @param from NFT 的原持有者（铸造时为 address(0)）
     * @param id NFT 的 token id
     * @param data 调用方传入的附加数据
     * @return onERC721Received.selector 表示接受该 NFT
     */
    function onERC721Received(address, address, uint256, bytes calldata) external virtual returns (bytes4) {
        return ERC721TokenReceiver.onERC721Received.selector;
    }
}
