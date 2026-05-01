// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {ERC20} from "../tokens/ERC20.sol";
import {SafeTransferLib} from "../utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "../utils/FixedPointMathLib.sol";

/// @notice Minimal ERC4626 tokenized Vault implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC4626.sol)
/*
 * 功能总结：
 * 极简的 ERC4626 代币化金库（Tokenized Vault）标准实现
 * 用户存入底层资产（asset，如 USDC/WETH），铸造出金库份额（shares）代币；
 * 份额代表对金库内总资产的按比例权益，可随时赎回取回底层资产
 *
 * 核心功能：
 * - 存款：deposit（按资产数量存）、mint（按想铸造的份额数量存）
 * - 取款：withdraw（按想取出的资产数量赎）、redeem（按份额数量赎）
 * - 会计换算：convertToShares / convertToAssets（资产与份额互换）
 * - 预览函数：previewDeposit/Mint/Withdraw/Redeem（预估执行结果，便于前端展示）
 * - 限额函数：maxDeposit/Mint/Withdraw/Redeem（返回调用者当前可操作的最大值）
 * - 钩子函数：beforeWithdraw、afterDeposit（子类可重写实现策略投资逻辑）
 *
 * 典型使用场景：
 * 1. 借贷协议存款凭证（如 Aave aToken、Compound cToken）
 *    用户存 1000 USDC → 金库发行 1000 vUSDC → 金库将 USDC 借出赚利息
 *    → totalAssets 增长到 1050 → 用户 redeem 1000 vUSDC → 取出 1050 USDC
 * 2. 收益聚合器（如 Yearn yvToken）
 *    afterDeposit() 将资产投入多层策略（Aave→Curve→自动复利）
 *    beforeWithdraw() 从策略赎回资产，totalAssets() = 余额 + 策略中资产
 * 3. 质押凭证（如 Lido wstETH）
 *    用户存 ETH → 金库交给验证节点质押 → PoS 奖励使 totalAssets 增长 → 份额自动升值
 *
 * 为什么需要 ERC4626 标准：
 *   标准化之前，Aave/Compound/Yearn 各自接口不同，聚合器需为每个协议写适配器
 *   ERC4626 统一了 deposit/mint/withdraw/redeem 四个入口 + 份额即 ERC20，
 *   实现了收益策略的"即插即用"——任何前端/聚合器对接一套接口即可接入所有金库
 *
 * 设计亮点：
 * 1. abstract 合约：totalAssets() 必须由子类实现，因为不同金库资产来源不同
 *    （可能是合约余额、借贷协议存款、LP 头寸等），基类无法预知
 * 2. 份额代币本身就是 ERC20：ERC4626 继承 ERC20，份额可转账、授权、组合到其他 DeFi
 * 3. 份额 decimals 与底层 asset 对齐：构造时 ERC20(_asset.decimals())，方便前端统一显示
 * 4. 舍入方向严格遵循"金库永远不吃亏"原则：
 *    - 存入时：份额向下取整（用户可能少拿一点点份额）
 *    - 取出时：份额向上取整（用户需要多销毁一点点份额换等量资产）
 *    防止通过舍入误差从金库"白嫖"资产
 * 5. 先转账再 mint / 先 burn 再转账：防御同类操作的重入套利（跨方向重入需额外加 nonReentrant，详见安全注意事项）
 * 6. 授权消耗：withdraw/redeem 支持代理赎回，type(uint256).max 视为无限授权不扣减
 * 7. 钩子模式：beforeWithdraw/afterDeposit 让子类轻松接入 Aave/Compound 等收益策略
 *
 * 安全注意事项：
 * - 本合约未内置 reentrancy guard。操作顺序（先转账再 mint / 先 burn 再转账）
 *   确保回调时状态偏向金库有利方向，可防御回调中再次调用同类操作的套利（如 deposit 中重入
 *   deposit、withdraw 中重入 withdraw）。但若底层资产的 transfer/transferFrom
 *   带有回调机制（如 ERC777、带 hook 的 ERC20、重写了 _beforeTokenTransfer 的 OZ ERC20），
 *   攻击者可在 deposit 的 safeTransferFrom 回调中调用 withdraw（跨方向重入）：
 *   此时 totalAssets 已增加但 totalSupply 未增加，withdraw 的份额换算公式失真，
 *   攻击者可用更少份额提取等量资产，造成微小套利并稀释其他持有人
 * - 除非已审计确认底层资产的 transfer 不带任何回调，否则子类应自行添加 nonReentrant 修饰符
 */
abstract contract ERC4626 is ERC20 {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 存款事件：caller 为实际调用者（msg.sender），owner 为接收份额的地址
    // assets 是存入的底层资产数量，shares 是铸造出的金库份额数量
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);

    // 取款事件：caller 为实际调用者，receiver 收到底层资产，owner 是份额被销毁的地址
    // 三者可能互不相同（如 A 代替 B 赎回资产转给 C），通过 allowance 控制授权
    event Withdraw(
        address indexed caller,
        address indexed receiver,
        address indexed owner,
        uint256 assets,
        uint256 shares
    );

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    // 底层资产代币（如 USDC、WETH），金库管理的标的
    // immutable：部署后绑定死，无法更换，避免治理风险
    ERC20 public immutable asset;

    // 构造函数：接收底层资产、份额代币名称、份额代币符号
    // 关键：份额的 decimals 直接继承自底层 asset，保证换算单位一致、前端显示友好
    constructor(ERC20 _asset, string memory _name, string memory _symbol) ERC20(_name, _symbol, _asset.decimals()) {
        asset = _asset;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT/WITHDRAWAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 存入指定数量的底层资产，按当前汇率铸造份额给 receiver
     * @dev 份额向下取整（previewDeposit → mulDivDown），少给一点点份额，金库不吃亏
     *      先转账再 mint：防止 ERC777 等带回调的代币重入攻击
     * @param assets   要存入的底层资产数量
     * @param receiver 接收份额的地址
     * @return shares  铸造给 receiver 的份额数量
     */
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // 向下取整可能导致小额存入换算出 0 份额
        // 若不检查，资产已转入金库但用户未获得任何份额，无法赎回 → 资产白送
        // 所以 shares == 0 时直接 revert，保护存款人
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // 必须先转账后 mint（先 Interaction 后 Effect，非标准 CEI 但同样防重入）：
        // 若反过来先 mint 后转账，ERC777 的 tokensToSend 回调会在转账时触发：
        //   此时 totalSupply 已增加（mint 了）但 totalAssets 未增加（钱未到）
        //   → 份额换算公式 shares = assets * totalSupply / totalAssets 中
        //     分子 totalSupply 膨胀、分母 totalAssets 不变，同样的存款算出更多份额
        //   → 攻击者在回调中再次 deposit 即可用相同的钱获得超额份额
        // 先转账后 mint：回调时份额未 mint、totalSupply 未变，换算公式正常，无法套利
        asset.safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        // 钩子：子类可在此将新存入的资产投入到收益策略中
        afterDeposit(assets, shares);
    }

    /**
     * @notice 指定要铸造的份额数量，反推需要存入多少资产
     * @dev 资产向上取整（previewMint → mulDivUp），多收一点点，金库不吃亏
     *      升序舍入保证 assets > 0（除非 shares = 0），无需检查 ZERO_ASSETS
     *      先转账再 mint：防止 ERC777 等带回调的代币重入攻击
     * @param shares   期望铸造的份额数量
     * @param receiver 接收份额的地址
     * @return assets  实际需要存入的底层资产数量
     */
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        // previewMint 向上取整（mulDivUp），assets 不会因舍入变成 0（除非 shares = 0），无需检查
        assets = previewMint(shares);

        // 同 deposit，必须先转账后 mint（先 Interaction 后 Effect，非标准 CEI 但同样防重入）：
        // 防止 ERC777 回调时 totalSupply 已膨胀但 totalAssets 未增加，导致份额换算失真
        asset.safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        // 同 deposit 钩子：子类可在此将新存入的资产投入到收益策略中
        afterDeposit(assets, shares);
    }

    /**
     * @notice 提取指定数量的底层资产，反推需要销毁多少 owner 的份额
     * @dev 份额向上取整（previewWithdraw → mulDivUp），多烧一点点，金库不吃亏
     *      若 caller != owner，需消耗 owner 对 caller 的 ERC20 allowance（按份额扣）
     *      无限授权（uint256.max）不扣减，省 gas
     *      先 burn 再转账：防止 ERC777 等带回调的代币重入攻击
     * @param assets   要提取的底层资产数量
     * @param receiver 接收底层资产的地址
     * @param owner    份额持有者地址（从中销毁份额）
     * @return shares  需要销毁的份额数量
     */
    function withdraw(uint256 assets, address receiver, address owner) public virtual returns (uint256 shares) {
        // previewWithdraw 向上取整（mulDivUp），shares 不会因舍入变成 0（除非 assets = 0），无需检查
        shares = previewWithdraw(assets);

        if (msg.sender != owner) {
            // 先读取到局部变量，避免后续再次 SLOAD；仅有限授权才需要扣减
            uint256 allowed = allowance[owner][msg.sender];

            // 无限授权（uint256.max）视为永久授权，不扣减以省 gas；否则按 shares 扣减
            if (allowed != type(uint256).max) allowance[owner][msg.sender] = allowed - shares;
        }

        // 钩子：子类可在此从策略中提取所需资产，确保金库有足够余额转出
        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        emit Withdraw(msg.sender, receiver, owner, assets, shares);

        // 必须先 burn 再转账（CEI 模式）：
        // 若反过来先转账后 burn，ERC777 的 tokensReceived 回调会在转账时触发：
        //   此时 totalAssets 已减少（钱已转出）但 totalSupply 未减少（shares 未 burn）
        //   → deposit 换算公式 shares = assets * totalSupply / totalAssets 中
        //     分子 totalSupply 偏大、分母 totalAssets 偏小，同样的存款算出更多份额
        //   → 攻击者在回调中 deposit，用更少的资产拿回等量份额，反复执行即可抽干金库
        // 先 burn 再转账：回调时 totalSupply 已减少，deposit 换算公式正常，无法套利
        asset.safeTransfer(receiver, assets);
    }

    /**
     * @notice 销毁指定数量的份额，按当前汇率取出对应底层资产给 receiver
     * @dev 资产向下取整（previewRedeem → mulDivDown），少给一点点，金库不吃亏
     *      降序舍入可能导致 assets = 0，require 防御避免用户白烧份额
     *      先 burn 再转账：防止 ERC777 等带回调的代币重入攻击
     * @param shares   要销毁的份额数量
     * @param receiver 接收底层资产的地址
     * @param owner    份额持有者地址（从中销毁份额）
     * @return assets  实际获得的底层资产数量
     */
    function redeem(uint256 shares, address receiver, address owner) public virtual returns (uint256 assets) {
        if (msg.sender != owner) {
            // 先读取到局部变量，避免后续再次 SLOAD；仅有限授权才需要扣减
            uint256 allowed = allowance[owner][msg.sender];

            // 无限授权（uint256.max）视为永久授权，不扣减以省 gas；否则按 shares 扣减
            if (allowed != type(uint256).max) allowance[owner][msg.sender] = allowed - shares;
        }

        // 向下取整可能导致少量份额换算出 0 资产
        // 若不检查，份额已 burn 但用户未获得任何资产 → 份额白烧
        // 所以 assets == 0 时直接 revert，保护赎回人
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        // 钩子：子类可在此从策略中提取所需资产，确保金库有足够余额转出
        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        emit Withdraw(msg.sender, receiver, owner, assets, shares);

        // 同 withdraw，必须先 burn 再转账（CEI 模式）：
        // 若反过来先转账后 burn，攻击者可在 ERC777 回调中 deposit，
        // 利用 totalAssets 已减但 totalSupply 未减的失真状态，用更少资产拿回等量份额
        asset.safeTransfer(receiver, assets);
    }

    /*//////////////////////////////////////////////////////////////
                            ACCOUNTING LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 金库当前管理的底层资产总量（含合约余额 + 投入策略中的部分）
     * @dev 抽象函数，必须由子类实现，因为资产可能分散在外部协议中，基类无法统一计算
     * @return 底层资产总量
     */
    function totalAssets() public view virtual returns (uint256);

    /**
     * @notice 资产 → 份额换算（向下取整 mulDivDown）
     * @dev 公式：shares = assets * totalSupply / totalAssets
     *      首次存入（supply == 0）时 1:1 映射，建立初始汇率
     * @param assets 底层资产数量
     * @return 对应的份额数量
     */
    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        // 缓存到局部变量，避免后续三元判断中重复 SLOAD
        uint256 supply = totalSupply;

        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    }

    /**
     * @notice 份额 → 资产换算（向下取整 mulDivDown）
     * @dev 公式：assets = shares * totalAssets / totalSupply
     *      首次存入（supply == 0）时 1:1 映射，与 convertToShares 对称
     * @param shares 份额数量
     * @return 对应的底层资产数量
     */
    function convertToAssets(uint256 shares) public view virtual returns (uint256) {
        // 缓存到局部变量，避免后续三元判断中重复 SLOAD
        uint256 supply = totalSupply;

        return supply == 0 ? shares : shares.mulDivDown(totalAssets(), supply);
    }

    /**
     * @notice 预估 deposit(assets) 能获得多少份额
     * @dev 向下取整（对用户不利、对金库有利）
     * @param assets 要存入的底层资产数量
     * @return 预计获得的份额数量
     */
    function previewDeposit(uint256 assets) public view virtual returns (uint256) {
        return convertToShares(assets);
    }

    /**
     * @notice 预估 mint(shares) 需要存入多少资产
     * @dev 公式：assets = shares * totalAssets / totalSupply（向上取整 mulDivUp）
     *      多收一点点，金库不吃亏
     * @param shares 期望铸造的份额数量
     * @return 预计需要存入的底层资产数量
     */
    function previewMint(uint256 shares) public view virtual returns (uint256) {
        // 缓存到局部变量，避免后续三元判断中重复 SLOAD
        uint256 supply = totalSupply;

        return supply == 0 ? shares : shares.mulDivUp(totalAssets(), supply);
    }

    /**
     * @notice 预估 withdraw(assets) 需要销毁多少份额
     * @dev 公式：shares = assets * totalSupply / totalAssets（向上取整 mulDivUp）
     *      多烧一点点，金库不吃亏
     * @param assets 要提取的底层资产数量
     * @return 预计需要销毁的份额数量
     */
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        // 缓存到局部变量，避免后续三元判断中重复 SLOAD
        uint256 supply = totalSupply;

        return supply == 0 ? assets : assets.mulDivUp(supply, totalAssets());
    }

    /**
     * @notice 预估 redeem(shares) 能取出多少资产
     * @dev 向下取整（对用户不利、对金库有利）
     * @param shares 要销毁的份额数量
     * @return 预计获得的底层资产数量
     */
    function previewRedeem(uint256 shares) public view virtual returns (uint256) {
        return convertToAssets(shares);
    }

    /*//////////////////////////////////////////////////////////////
                     DEPOSIT/WITHDRAWAL LIMIT LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 给定地址单次最大可存入的资产量
     * @dev 默认无上限；子类可重写加入白名单、封顶等限制
     * @return 最大可存入的底层资产数量
     */
    function maxDeposit(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @notice 给定地址单次最大可铸造的份额量
     * @dev 默认无上限；子类可重写以施加限制
     * @return 最大可铸造的份额数量
     */
    function maxMint(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @notice owner 当前可提取的最大底层资产量
     * @dev 默认等于 owner 持有份额的换算值（convertToAssets）
     * @param owner 份额持有者地址
     * @return 最大可提取的底层资产数量
     */
    function maxWithdraw(address owner) public view virtual returns (uint256) {
        return convertToAssets(balanceOf[owner]);
    }

    /**
     * @notice owner 当前可赎回的最大份额数
     * @dev 默认等于 owner 的份额余额
     * @param owner 份额持有者地址
     * @return 最大可赎回的份额数量
     */
    function maxRedeem(address owner) public view virtual returns (uint256) {
        return balanceOf[owner];
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HOOKS LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 取款前钩子：在 _burn 和资产转出之前调用
     * @dev 典型用途：从外部策略（如 Aave、Compound）赎回足够资产，保证金库流动性
     * @param assets 被提取的底层资产数量
     * @param shares 被销毁的份额数量
     */
    function beforeWithdraw(uint256 assets, uint256 shares) internal virtual {}

    /**
     * @notice 存款后钩子：在资产转入和 _mint 之后调用
     * @dev 典型用途：将新存入的资产投入收益策略，让闲置资金产生利息
     * @param assets 存入的底层资产数量
     * @param shares 铸造的份额数量
     */
    function afterDeposit(uint256 assets, uint256 shares) internal virtual {}
}
