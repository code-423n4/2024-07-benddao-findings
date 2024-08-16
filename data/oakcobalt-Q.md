### Low-01  PriceOracle can be deployed to L2 but doesn't check L2 sequencer status
**Instance(1)**
According to [Readme](https://github.com/code-423n4/2024-07-benddao/tree/main?tab=readme-ov-file#general-questions), the contracts in scope are also intended to be deployed on L2 such as optimism and arbitrum. Optimistic roll-up has a sequencer that executes tractions and batching transactions.

Based on [chainlink doc](https://docs.chain.link/data-feeds/l2-sequencer-feeds#overview), it’s important to check L2 sequencer status when consume chainlink price feed on L2. 

However, current getAssetPriceFromChainlink() doesn’t check L2 sequencer status.
```solidity
//src/PriceOracle.sol
  function getAssetPriceFromChainlink(address asset) public view returns (uint256) {
    AggregatorV2V3Interface sourceAgg = assetChainlinkAggregators[asset];
    require(address(sourceAgg) != address(0), Errors.ASSET_AGGREGATOR_NOT_EXIST);
    (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = sourceAgg.latestRoundData();
    require(answer > 0, Errors.ASSET_PRICE_IS_ZERO);
    //@audit  Medium: PriceOracle has invalid check on price staleness. 
    require(updatedAt != 0, Errors.ORACLE_PRICE_IS_STALE);
    require(answeredInRound >= roundId, Errors.ORACLE_PRICE_IS_STALE);
    return uint256(answer);
  }
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/PriceOracle.sol#L118)

When L2 sequencer is offline or down, price data becomes outdated or can be predictable, continuing allow price feed might lead to window of exploits of insecure price data.

Recommendations:
For L2 deployment, reference chainlink’s sample code to check L2 sequencer uptime. (https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code)

### Low-02 MAX_NUMBER_OF_ASSET can be exceeded due to invalid check
**Instance(2)**
MAX_NUMBER_OF_ASSET limits the total number of asset allowed to be added in a pool.

However, `MAX_NUMBER_OF_ASSET` can be exceeded due to an invalid check. There are two instances.

(1)
```solidity
//src/libraries/logic/ConfigureLogic.sol
  function executeAddAssetERC20(address msgSender, uint32 poolId, address asset) internal {
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();

    DataTypes.PoolData storage poolData = ps.poolLookup[poolId];
    _validateCallerAndPool(msgSender, ps, poolData);

    DataTypes.AssetData storage assetData = poolData.assetLookup[asset];
    require(assetData.assetType == 0, Errors.ASSET_ALREADY_EXISTS);

|>  require(poolData.assetList.length() <= Constants.MAX_NUMBER_OF_ASSET, Errors.ASSET_NUMBER_EXCEED_MAX_LIMIT);

    assetData.underlyingAsset = asset;
    assetData.assetType = uint8(Constants.ASSET_TYPE_ERC20);
    assetData.underlyingDecimals = IERC20MetadataUpgradeable(asset).decimals();

    InterestLogic.initAssetData(assetData);

    bool isAddOk = poolData.assetList.add(asset);
    require(isAddOk, Errors.ENUM_SET_ADD_FAILED);

    emit Events.AddAsset(poolId, asset, uint8(Constants.ASSET_TYPE_ERC20));
  }
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/ConfigureLogic.sol#L196)

(2)
```solidity
  function executeAddAssetERC721(address msgSender, uint32 poolId, address asset) internal {
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();

    DataTypes.PoolData storage poolData = ps.poolLookup[poolId];
    _validateCallerAndPool(msgSender, ps, poolData);

|>  require(poolData.assetList.length() <= Constants.MAX_NUMBER_OF_ASSET, Errors.ASSET_NUMBER_EXCEED_MAX_LIMIT);

    DataTypes.AssetData storage assetData = poolData.assetLookup[asset];
    require(assetData.assetType == 0, Errors.ASSET_ALREADY_EXISTS);

    assetData.underlyingAsset = asset;
    assetData.assetType = uint8(Constants.ASSET_TYPE_ERC721);

    bool isAddOk = poolData.assetList.add(asset);
    require(isAddOk, Errors.ENUM_SET_ADD_FAILED);

    emit Events.AddAsset(poolId, asset, uint8(Constants.ASSET_TYPE_ERC721));
  }
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/ConfigureLogic.sol#L229)

Because assetList is added after the check. The correct check should be `poolData.assetList.length() < Constants.MAX_NUMBER_OF_ASSET`

Recommendations:
Change the require check into `poolData.assetList.length() < Constants.MAX_NUMBER_OF_ASSET`

### Low-03 `accruedFee` is accounted into `availableLiquidity` for at loan repayment, risk of protocolFee loss in edge cases
**Instance(1)**
`assetData.accruedFee` is deducted from a portion of debt interests and is increased every time totalDebt compounds. (InterestLogic::updateInterestIndexs -> _accrueFeeToTreasury)
```solidity
//src/libraries/logic/InterestLogic.sol
  function _accrueFeeToTreasury(
    DataTypes.AssetData storage assetData,
    DataTypes.GroupData storage groupData,
    uint256 prevGroupBorrowIndex
  ) internal {
...
    //debt accrued is the sum of the current debt minus the sum of the debt at the last update
    vars.totalDebtAccrued = vars.currTotalBorrow - vars.prevTotalBorrow;

    vars.amountToMint = vars.totalDebtAccrued.percentMul(assetData.feeFactor);

    if (vars.amountToMint != 0) {
      assetData.accruedFee += vars.amountToMint.rayDiv(assetData.supplyIndex).toUint128();
    }
  }
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/InterestLogic.sol#L248)

The `assetData.accruedFee` is only accounting until funds are transferred in the pool when the corresponding loan responsible for the accounting is repaid. (e.g. IsolateLogic::executeIsolateRepay() → VaultLogic.sol::erc20TransferInLiquidity())

The problem is when a loan is repaid, the entire repayment ( principal + interest including accruedfee portion) is accounted in `availableLiquidity`. This mean, when a loan is repaid, the acrruedFee can also be borrowed by anyone. 
```solidity
//src/libraries/logic/IsolateLogic.sol
  function executeIsolateRepay(InputTypes.ExecuteIsolateRepayParams memory params) internal returns (uint256) {
...
    // transfer underlying asset from borrower to pool
    VaultLogic.erc20TransferInLiquidity(debtAssetData, params.msgSender, vars.totalRepayAmount);
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/IsolateLogic.sol#L159)
```solidity
//src/libraries/logic/VaultLogic.sol
  function erc20TransferInLiquidity(DataTypes.AssetData storage assetData, address from, uint256 amount) internal {
...
|>  assetData.availableLiquidity += amount;
    IERC20Upgradeable(asset).safeTransferFrom(from, address(this), amount);
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/VaultLogic.sol#L432)
In normal circumstance where loan can be reliably repaid, this is not an issue. But when bad debt occurs in the protocol, treasury's accruedFee cannot be guaranteed. Treasury's accruedFee is exposed the same risks as other user's supplied ERC20 assets, risk of loss in protocol fees.

Recommendations:
Consider implement accounting for the total interest accumulated by a loan, and set aside the proportional fee accruals from `availableLiquidity`.

### Low-04 Outdated borrowIndex/supplyIndex is used in `viewGetUserCrossLiquidateData()`
**Instance(1)**
In state changing flows that consumes borrowIndex/supplyIndex, these indexes will be updated first to ensure only the updated borrowIndex/supplyIndex will be used for calculation.

However, in this non-state changing method `viewGetUserCrossLiquidateData()`. borrowIndex/supplyIndex is not re-calculated based on block.timestamp. Instead, old  indexes are pulled and directly used in `_calculateUserERC20Debt()`. This result in incorrect `actualDebtToLiquidate` to be used by any connecting integrations.
```solidity
//src/libraries/logic/LiquidationLogic.sol

  function viewGetUserCrossLiquidateData(
    InputTypes.ViewGetUserCrossLiquidateDataParams memory getDataParams
  ) internal view returns (uint256 actualCollateralToLiquidate, uint256 actualDebtToLiquidate) {
...
    DataTypes.PoolData storage poolData = ps.poolLookup[getDataParams.poolId];
    DataTypes.AssetData storage collateralAssetData = poolData.assetLookup[getDataParams.collateralAsset];
|>  DataTypes.AssetData storage debtAssetData = poolData.assetLookup[getDataParams.debtAsset];
...
    if (collateralAssetData.assetType == Constants.ASSET_TYPE_ERC20) {
      InputTypes.ExecuteCrossLiquidateERC20Params memory erc20Params;
      erc20Params.borrower = getDataParams.borrower;
      erc20Params.debtToCover = getDataParams.debtAmount;

      (vars.userTotalDebt, vars.actualDebtToLiquidate) = _calculateUserERC20Debt(
        poolData,
|>      debtAssetData,
        erc20Params,
        vars.userAccountResult.healthFactor
      );
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/LiquidationLogic.sol#L557)

Recommendations:
Consider using InterestLogic::[getNormalizedSupplyIncome](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/InterestLogic.sol#L49) / [getNormalizedBorrowDebt](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/InterestLogic.sol#L67), to calculate latest indexes. 

### Low-05 `erc721TokenData.lockerAddr` not reset after loan liquidation
**Instance(1)**
When an isolate loan is liquidated, a liquidator can immediately receive the ERC721 token or directly supply the acquired ERC721 token. In both cases, the existing ERC721TokenData.lockAddr is not cleared.
```solidity
//src/libraries/logic/IsolateLogic.sol
  function executeIsolateLiquidate(InputTypes.ExecuteIsolateLiquidateParams memory params) internal {
...
    // transfer erc721 to bidder
    if (params.supplyAsCollateral) {
      VaultLogic.erc721TransferIsolateSupplyOnLiquidate(nftAssetData, params.msgSender, params.nftTokenIds);
    } else {
      VaultLogic.erc721DecreaseIsolateSupplyOnLiquidate(nftAssetData, params.nftTokenIds);

      VaultLogic.erc721TransferOutLiquidity(nftAssetData, params.msgSender, params.nftTokenIds);
    }
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/IsolateLogic.sol#L471-L478)

This is an error because when `ERC721TokenData.lockAddr != address(0)` this means the loan is actively borrowed against (either in isolate loan or a yieldBorrow).

Since the liquidator already acquired the ERC721 token and it's no longer locked in a loan or staking contract. `ERC721TokenData.lockAddr` should be reset to address(0). 

Failing to reset `ERC721TokenData.lockAddr` to address(0) when the loan is deleted, can pose issues for future withdrawal or borrowing that involves the nft token.

For example,
(1) if the liquidator wishes to use the nft token for restaking (YieldStakingBase::stake), the tx will revert due to [failing vars.nftLockerAddr == address(0) check](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/yield/YieldStakingBase.sol#L227).
 

(2) if the liquidator wishes to withdraw the nft token, the tx will revert at ValidateLogic::validateWithdrawERC721, due to [failing vars.nftLockerAddr == address(0) check](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/libraries/logic/ValidateLogic.sol#L171).  

Recommendations:
In executeIsolateLiquidate(), tokenData.lockAddr to address(0) by `VaultLogic.erc721SetTokenLockerAddr()`.

### Low-06 Global pausing feature will also pause liquidation, risks of protocol insolvency.
**Instance(3)**
Although pausing is an intended admin feature, it could be argued that indiscriminately pausing liquidation functions can be risky. For whatever reason global pause is activated, and no liquidation can be executed which puts the protocol's solvency at risk after the pausing is lifted. 

Periods of market volatility during pausing could put the protocol solvency at risk. Liquidation can not be executed when the protocol needs it the most.

(1)
```solidity
//src/modules/CrossLiquidation.sol
  function crossLiquidateERC721(
    uint32 poolId,
    address borrower,
    address collateralAsset,
    uint256[] calldata collateralTokenIds,
    address debtAsset,
    bool supplyAsCollateral
  ) public payable whenNotPaused nonReentrant {
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/modules/CrossLiquidation.sol#L68)
(2)
```solidity
  function crossLiquidateERC20(
    uint32 poolId,
    address borrower,
    address collateralAsset,
    address debtAsset,
    uint256 debtToCover,
    bool supplyAsCollateral
  ) public payable whenNotPaused nonReentrant {
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/modules/CrossLiquidation.sol#L28)
(3)
```solidity
  function isolateAuction(
    uint32 poolId,
    address nftAsset,
    uint256[] calldata nftTokenIds,
    address asset,
    uint256[] calldata amounts
  ) public payable whenNotPaused nonReentrant 
...
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/modules/IsolateLiquidation.sol#L26)

Recommendations:
Consider not allowing pausing liquidation globally. Consider only allowing segregated asset-level liquidation pause in edge conditions.

### Low-07 Any NFT staking position that exceeds 1000 stETH yield amount cannot be withdrawn, resulting in funds locked. 
**Instance(1)**
In Lido’s [WithdrawRequest(WithdrawalQueue.sol) implementation](https://github.com/lidofinance/lido-dao/blob/5fcedc6e9a9f3ec154e69cff47c2b9e25503a78a/contracts/0.8.9/WithdrawalQueue.sol#L395-L400), only a withdraw request with stETH amount within MIN_STETH_WITHDRAWAL_AMOUNT, MAX_STETH_WITHDRAWAL_AMOUNT ( [100, 1000ether]) can be processed. 

If the yieldAmount exceeds 1000ether, the withdrawal request has to be split into several requests.

The problem is current implementation of YieldEthStakingLido.sol and YieldStakingBase.sol do not allow splitting withdrawal of a nft token staking position (yieldStakeData).
```solidity
//src/yield/YieldStakingBase.sol
  function _unstake(uint32 poolId, address nft, uint256 tokenId, uint256 unstakeFine) internal virtual {
...
     //@audit only full unstake. sd.yieldShare is the total staking amount of the nft token
|>   sd.withdrawAmount = convertToYieldAssets(address(vars.yieldAccout), sd.yieldShare);
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/yield/YieldStakingBase.sol#L340)

Depending on the leverageFactor, nft token price, and the amount of yield increase, the allowable yieldBorrow can exceed the the nft token price multiple times. In an edge case where yieldAmount exceeds 1000 ether stETH. The staking position cannot be unstaked. The yield will be locked.

Flows: yieldStakingBase::unstake -> YieldEthStakingLido::protocolRequestWithdrawal  -> WithdrawRequest::requestWithdrawals -> WithdrawRequest::_checkWithdrawalRequestAmount reverts due to [failing MAX_STETH_WITHDRAWAL_AMOUNT check](https://github.com/lidofinance/lido-dao/blob/5fcedc6e9a9f3ec154e69cff47c2b9e25503a78a/contracts/0.8.9/WithdrawalQueue.sol#L395-L400).

Recommendations:
Consider allowing the user to perform partial unstake, by allowing the user to specify a portion of the total sd.withdrawAmount.

### Low-08 Vulnerable calculateHealthFactor implementation might inflate user’s total collaterals and yields.
**Instance(1)**
In YieldStakingBase.sol, healthFactor is calculated as (totalNftValue + totalYieldValue) / totalDebtValue. 
```solidity
  function calculateHealthFactor(
    address nft,
    YieldNftConfig storage nc,
    YieldStakeData storage sd
  ) internal view virtual returns (uint256) {
    uint256 nftPrice = getNftPriceInUnderlyingAsset(nft);
    uint256 totalNftValue = nftPrice.percentMul(nc.liquidationThreshold);

    (, uint256 totalYieldValue) = _getNftYieldInUnderlyingAsset(sd);
    uint256 totalDebtValue = _getNftDebtInUnderlyingAsset(sd);

    return (totalNftValue + totalYieldValue).wadDiv(totalDebtValue);
  }
}
```
(https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/yield/YieldStakingBase.sol#L691)

The issue is that `totalYieldValue` is not the actual yield/ profit generated from user’s staking. `totalYieldValue` is essentially [the receipt token balance](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/src/yield/YieldStakingBase.sol#L651) (stETH, eETH , sDAI, etc) for the user’s underlying token staking. Its value represents staking + yield. 

Because in YieldStakingBase.sol, the user's staked underlying assets come from debt(). `calculateHealthFactor()` essentially counts the user’s debt at both the denominator and numerator, which is incorrect.

A further inspection in the current unit test shows the threshold of healthFactor (`unstakeHeathFactor`) is [set uniformly as 1.05e18](https://github.com/code-423n4/2024-07-benddao/blob/117ef61967d4b318fc65170061c9577e674fffa1/script/InitConfigYield.s.sol#L100). This indicates the correct implementation should be (totalNftValue + yield ) /  totalDebtValue, removing the debt value from the numerator.

Suppose totalNftValue is 1 ether WETH (after liquidation threshold discount), and the user borrowed 0.5 ether WETH and staked 0.5 ether WETH in ether.fi, which means the user initially receives 0.5 ether eETH in their yieldAccount. suppose eETH oracle price is 1 ether WETH.

At the time of staking, the current health factor’s implementation will be (1 ether + 0.5 ether) / 0.5 ether → 3. But because no yield has been generated at this point, the expected health factor should be (1 ether + 0 ) / 0.5 ether → 2.

Recommendations:
Consider this implementation (totalNFTValue + currentYieldAmount - originalNFTYield) / totalDebValue. This requires storing the original yieldAmount received by the NFT position.


