// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Minimalist and gas efficient standard ERC1155 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol)
/*
 * 功能总结：
 * 现代化、极简、gas 高效的 ERC-1155 多代币标准实现
 *
 * 核心功能：
 * - ERC1155 标准：safeTransferFrom、safeBatchTransferFrom、balanceOf、balanceOfBatch、setApprovalForAll
 * - ERC165 接口检测：supportsInterface
 * - 内部 _mint / _burn / _batchMint / _batchBurn：供子合约继承使用
 *
 * 设计亮点：
 * 1. abstract 合约：不能直接部署，必须由子合约继承并实现 uri
 * 2. 同质化 + 非同质化统一模型：一个合约管理多种代币（fungible 和 non-fungible 共存）
 * 3. 只有全局授权（setApprovalForAll），没有 ERC20 的单个 approve 或 ERC721 的单 token approve
 * 4. 所有转移都是 safe 的：必须通过 safeTransferFrom / safeBatchTransferFrom，没有不安全的 transferFrom
 * 5. 批量操作原生支持：safeBatchTransferFrom、balanceOfBatch、_batchMint、_batchBurn，单笔交易操作多种代币
 * 6. 循环计数器 unchecked ++i：数组长度不可能溢出 uint256，省去溢出检查
 *
 * 与 ERC20/ERC721 的关键区别：
 * - ERC20：单一同质化代币，一个合约 = 一种代币
 * - ERC721：单一非同质化代币，一个合约 = 一个 NFT 集合，每个 id 唯一
 * - ERC1155：多代币标准，一个合约 = 多种代币，每个 id 可以有任意数量（amount=1 即 NFT，amount>1 即 FT）
 */
abstract contract ERC1155 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 单个转移事件：operator 将 amount 个 id 代币从 from 转给 to
    // from == address(0) 表示铸造，to == address(0) 表示销毁
    // operator 是实际调用者（msg.sender），可能是 from 本人或被全局授权的 operator
    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 amount
    );

    // 批量转移事件：operator 将多种代币从 from 批量转给 to
    // ids 和 amounts 一一对应，ids[i] 的转移数量是 amounts[i]
    // 与 ERC721 的区别：ERC721 每次转移只触发一个 Transfer 事件，
    // ERC1155 批量转移只触发一个 TransferBatch 事件（而非 N 个 TransferSingle）
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] amounts
    );

    // 全局授权事件：owner 将所有代币（所有 id）的操作权授予/撤销 operator
    // 与 ERC721 的 ApprovalForAll 语义相同
    // ERC1155 没有单个 id 的 approve，只有全局授权
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    // 元数据 URI 变更事件：id 对应的元数据 URI 发生变化
    // ERC1155 标准要求：当 URI 变更时必须触发此事件
    // ERC20/ERC721 没有此事件
    event URI(string value, uint256 indexed id);

    /*//////////////////////////////////////////////////////////////
                             ERC1155 STORAGE
    //////////////////////////////////////////////////////////////*/

    // 地址 → token id → 余额
    // 与 ERC20 的 mapping(address => uint256) 和 ERC721 的 mapping(uint256 => address) 都不同
    // ERC1155 需要二维映射：同一地址可以持有多种 id，每种 id 有独立余额
    mapping(address => mapping(uint256 => uint256)) public balanceOf;

    // owner → operator → 是否全局授权
    // 与 ERC721 的 isApprovedForAll 相同
    // ERC1155 没有 ERC721 的 getApproved（单 token 授权），只有全局授权
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    /*//////////////////////////////////////////////////////////////
                             METADATA LOGIC
    //////////////////////////////////////////////////////////////*/

    // 返回指定 id 的元数据 URI，子合约必须实现
    // ERC1155 的 URI 方案支持 {id} 占位符替换，如 "https://api.example.com/token/{id}.json"
    // 客户端需将 {id} 替换为实际的十六进制 token id（小写，无 0x 前缀，64 字符零填充）
    function uri(uint256 id) public view virtual returns (string memory);

    /*//////////////////////////////////////////////////////////////
                              ERC1155 LOGIC
    //////////////////////////////////////////////////////////////*/

    // 全局授权：授权或撤销 operator 对 msg.sender 所有代币（所有 id）的操作权
    // 与 ERC721 的 setApprovalForAll 完全相同
    // ERC1155 没有单个 id 的 approve 函数：要么全部授权，要么不授权
    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;

        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // 安全转移：将 amount 个 id 代币从 from 转给 to
    // ERC1155 标准要求所有转移都必须是 safe 的
    //
    // 与 ERC721 transferFrom 的区别：
    // 1. ERC721 有不安全的 transferFrom + 安全的 safeTransferFrom，ERC1155 只有 safeTransferFrom
    // 2. ERC721 转移一个唯一 id，ERC1155 转移指定 id 的 amount 个
    // 3. ERC721 权限检查三选一（owner/operator/approved），ERC1155 只有两选一（owner/operator）
    // 4. ERC721 转移后清除单个授权（delete getApproved[id]），ERC1155 无此操作
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public virtual {
        // 权限检查：调用者必须是 from 本人，或被 from 全局授权的 operator
        // 与 ERC721 相比少了 getApproved 检查（ERC1155 没有单 token 授权）
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");

        // 余额更新：使用 checked 算术（Solidity 0.8+ 默认行为）
        // -= 会自动检查下溢（from 余额不足时 revert）
        // += 也会检查溢出（但 uint256 上限足够大，实际不可能触发）
        // 与 ERC721 不同：ERC721 用 unchecked 因为 owner 已验证余额 ≥ 1，
        // 但 ERC1155 的 amount 可以是任意值，不能 unchecked -=
        balanceOf[from][id] -= amount;
        balanceOf[to][id] += amount;

        emit TransferSingle(msg.sender, from, to, id, amount);

        // 安全检查（先转移后检查，与 ERC721 的 safeTransferFrom 思路相同）：
        // - to 是 EOA（code.length == 0）：只需确保 to 不是零地址
        // - to 是合约：调用 onERC1155Received，要求返回正确的 selector
        //
        // 与 ERC721 的区别：ERC721 的 transferFrom 单独检查 to != address(0)，
        // 而 ERC1155 将零地址检查和安全回调合并到一个 require 中
        // 即 ERC1155 没有单独的零地址检查，靠三元表达式统一处理
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, from, id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    // 批量安全转移：将多种代币从 from 批量转给 to
    // ids[i] 对应转移 amounts[i] 个，两个数组必须等长
    // 批量操作比多次调用 safeTransferFrom 更省 gas（共享权限检查、只触发一个事件、只做一次安全回调）
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public virtual {
        require(ids.length == amounts.length, "LENGTH_MISMATCH");

        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");

        // 将 id 和 amount 声明在循环外部，循环内只赋值
        // 省约 15 gas/次迭代（避免每次迭代重新声明栈变量）
        uint256 id;
        uint256 amount;

        for (uint256 i = 0; i < ids.length; ) {
            id = ids[i];
            amount = amounts[i];

            // checked 算术：-= 自动检查余额不足
            balanceOf[from][id] -= amount;
            balanceOf[to][id] += amount;

            // 数组长度不可能超过 uint256 最大值，循环计数器 ++i 不会溢出
            unchecked {
                ++i;
            }
        }

        // 批量转移只触发一个 TransferBatch 事件（不是 N 个 TransferSingle）
        emit TransferBatch(msg.sender, from, to, ids, amounts);

        // 安全回调：合约接收方必须实现 onERC1155BatchReceived（不是 onERC1155Received）
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    // 批量查询余额：查询多个 (owner, id) 对的余额
    // owners[i] 持有 ids[i] 的数量 → balances[i]
    // 注意：owners 和 ids 不是"所有 owner 的所有 id"，而是一一对应的查询对
    function balanceOfBatch(
        address[] calldata owners,
        uint256[] calldata ids
    ) public view virtual returns (uint256[] memory balances) {
        require(owners.length == ids.length, "LENGTH_MISMATCH");

        balances = new uint256[](owners.length);

        // 循环计数器 ++i 不可能溢出 uint256
        unchecked {
            for (uint256 i = 0; i < owners.length; ++i) {
                balances[i] = balanceOf[owners[i]][ids[i]];
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * ERC165 接口检测：声明本合约支持哪些接口
     * ERC1155 规范（EIP-1155）要求必须实现此函数
     *
     * 支持的接口：
     * - 0x01ffc9a7：ERC165（supportsInterface()）
     * - 0xd9b67a26：ERC1155（balanceOf()、balanceOfBatch()、safeTransferFrom()、
     *               safeBatchTransferFrom()、setApprovalForAll()、isApprovedForAll()）
     * - 0x0e89341c：ERC1155MetadataURI（uri()）
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0xd9b67a26 || // ERC165 Interface ID for ERC1155
            interfaceId == 0x0e89341c; // ERC165 Interface ID for ERC1155MetadataURI
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    // 单个铸造：铸造 amount 个 id 代币给 to
    // 与 ERC721 _mint 的区别：
    // 1. ERC721 每个 id 只能铸造一次（require _ownerOf[id] == 0），ERC1155 同一 id 可反复铸造叠加
    // 2. ERC721 _mint 不做安全回调（需要 _safeMint），ERC1155 _mint 自带安全回调
    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal virtual {
        balanceOf[to][id] += amount;

        // from == address(0) 表示铸造
        emit TransferSingle(msg.sender, address(0), to, id, amount);

        // 安全回调：与 safeTransferFrom 相同的检查逻辑
        // from 参数传 address(0) 表示这是铸造操作
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, address(0), id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    // 批量铸造：铸造多种代币给 to
    // ids[i] 铸造 amounts[i] 个，两个数组必须等长
    //
    // 为什么数组参数是 memory 而非 calldata？
    // - internal 函数的调用方可能在内部动态构造数组（如 new uint256[](n)），
    //   Solidity 在合约内部调用时不允许将 memory 引用传给 calldata 参数，所以必须用 memory
    // - public/external 函数（如 safeBatchTransferFrom）用 calldata，
    //   因为外部调用时 Solidity 自动将 memory 编码为 calldata，不受此限制
    function _batchMint(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        uint256 idsLength = ids.length; // 缓存到栈变量，避免每次循环读 memory（省 MLOAD）

        require(idsLength == amounts.length, "LENGTH_MISMATCH");

        for (uint256 i = 0; i < idsLength; ) {
            balanceOf[to][ids[i]] += amounts[i];

            // 数组长度不可能超过 uint256 最大值
            unchecked {
                ++i;
            }
        }

        // from == address(0) 表示铸造
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);

        // 安全回调：调用 onERC1155BatchReceived（不是 onERC1155Received）
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, address(0), ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    // 批量销毁：销毁 from 的多种代币
    // ids[i] 销毁 amounts[i] 个
    // 数组参数为 memory 而非 calldata：原因同 _batchMint
    // 与 _batchMint 的区别：不做安全回调（销毁不涉及接收方）
    // 与 ERC721 _burn 的区别：ERC721 会清除 getApproved[id]，ERC1155 没有单 token 授权所以无需清理
    function _batchBurn(address from, uint256[] memory ids, uint256[] memory amounts) internal virtual {
        uint256 idsLength = ids.length; // 缓存到栈变量，省 MLOAD

        require(idsLength == amounts.length, "LENGTH_MISMATCH");

        for (uint256 i = 0; i < idsLength; ) {
            // checked 算术：-= 自动检查余额不足
            balanceOf[from][ids[i]] -= amounts[i];

            // 数组长度不可能超过 uint256 最大值
            unchecked {
                ++i;
            }
        }

        // to == address(0) 表示销毁
        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
    }

    // 单个销毁：销毁 from 的 amount 个 id 代币
    // 不做安全回调（销毁不涉及接收方）
    // 不做零地址检查：如果 from 是零地址，balanceOf[address(0)][id] 默认为 0，-= 会自动 revert
    function _burn(address from, uint256 id, uint256 amount) internal virtual {
        // checked 算术：余额不足时自动 revert（Solidity 0.8+ 默认行为）
        balanceOf[from][id] -= amount;

        // to == address(0) 表示销毁
        emit TransferSingle(msg.sender, from, address(0), id, amount);
    }
}

/// @notice A generic interface for a contract which properly accepts ERC1155 tokens.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol)
/*
 * ERC1155 接收器接口
 * 任何想通过 safeTransferFrom / safeBatchTransferFrom / _mint / _batchMint 接收 ERC1155 代币的合约
 * 都必须实现此接口的两个回调函数
 *
 * 与 ERC721TokenReceiver 的区别：
 * - ERC721TokenReceiver 只有一个回调（onERC721Received）
 * - ERC1155TokenReceiver 有两个回调：onERC1155Received（单个）和 onERC1155BatchReceived（批量）
 * - ERC1155 回调多了 amount 参数（ERC721 每个 id 就是一个，不需要 amount）
 *
 * 设计决策：
 * - abstract contract 而非 interface：提供默认实现（直接返回正确 selector），
 *   子合约可直接继承而不必自己实现（如果不需要自定义逻辑）
 * - 子合约可覆写添加自定义验证（如只接受特定 id、解码 data 执行后续操作）
 */
abstract contract ERC1155TokenReceiver {
    // 单个转移/铸造的回调
    // operator：实际调用者（msg.sender）
    // from：代币原持有者（铸造时为 address(0)）
    // id：代币 id
    // amount：转移数量
    // data：调用方传入的附加数据
    // 返回值：必须返回 onERC1155Received.selector（即 0xf23a6e61）
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155Received.selector;
    }

    // 批量转移/铸造的回调
    // 参数含义与 onERC1155Received 相同，但 id/amount 变为数组
    // 返回值：必须返回 onERC1155BatchReceived.selector（即 0xbc197c81）
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155BatchReceived.selector;
    }
}
