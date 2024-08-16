## Findings Summary

| Label | Description |
| - | - |
| [L-01] | PriceOracle.sol needs to add MAX_DELAY to avoid Stale Price|
| [L-02] | executeCrossBorrowERC20() need to execute `updateInterestIndexes()` before `validateCrossBorrowERC20Basic()`|
| [L-03] | isolate auction process, token blacklisted users may block the bidding process|
| [L-04] | executeIsolateLiquidate() need to add `maxDebtToLiquidate` limit to avoid paying more debt than expected|
| [L-05] | The supplyCap limit may be subject to a DOS attack used to maliciously prevent users from depositing collateral, leading to liquidation |
| [L-06] | erc721TransferIsolateSupplyOnLiquidate() Missing cancel delegate.|

## [L-01] PriceOracle.sol needs to add MAX_DELAY to avoid Stale Price
Currently `PriceOracle.sol` only restricts `updatedAt ! = 0` and `answeredInRound >= roundId`.
lacks the restriction `MAX_DELAY`.

According to the chainlink documentation
https://docs.chain.link/data-feeds#check-the-timestamp-of-the-latest-answer
>Your application should track the latestTimestamp variable or use the updatedAt value from the latestRoundData() function to make sure that the latest answer is recent enough for your application to use it. If your application detects that the reported answer is not updated within the heartbeat or within time limits that you determine are acceptable for your application, pause operation or switch to an alternate operation mode while identifying the cause of the delay.

>During periods of low volatility, the heartbeat triggers updates to the latest answer. Some heartbeats are configured to last several hours, so your application should check the timestamp and verify that the latest answer is recent enough for your application.


Recommendation:

Add MAX_DELAY

```diff
contract PriceOracle is IPriceOracle, Initializable {
...
  function getAssetPriceFromChainlink(address asset) public view returns (uint256) {
    AggregatorV2V3Interface sourceAgg = assetChainlinkAggregators[asset];
    require(address(sourceAgg) != address(0), Errors.ASSET_AGGREGATOR_NOT_EXIST);
    //@audit-med OK 没有检查L2的Seq挂了没?
    (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = sourceAgg.latestRoundData();
    require(answer > 0, Errors.ASSET_PRICE_IS_ZERO);
    require(updatedAt != 0, Errors.ORACLE_PRICE_IS_STALE);
    require(answeredInRound >= roundId, Errors.ORACLE_PRICE_IS_STALE);
+    require(block.timestamp -  updatedAt >= MAX_DELAY, Errors.ORACLE_PRICE_IS_STALE);
    return uint256(answer);
  }
```

## [L-02] executeCrossBorrowERC20() need to execute `updateInterestIndexes()` before `validateCrossBorrowERC20Basic()`
in `BorrowLogic.executeCrossBorrowERC20()`
Execute the following steps
1. ValidateLogic.validateCrossBorrowERC20Basic(params, poolData, assetData);
2. InterestLogic.updateInterestIndexes(poolData, assetData);
3. ValidateLogic.validateCrossBorrowERC20Account(params, poolData, assetData, priceOracle);

In the first step, execute `validateCrossBorrowERC20Basic()` first.
This method checks `borrowCap`, which uses `groupData.borrowIndex`.
But it doesn't execute `InterestLogic.updateInterestIndexes()` first, which doesn't use the latest `groupData.borrowIndex`.

Impact.
`ValidateLogic.validateCrossBorrowERC20Basic()` is not using the latest `groupData.borrowIndex`.
Checking the `borrowCap` is not accurate, it will be smaller than it actually is.

Suggestion.
execute `updateInterestIndexs()` first
```diff
  function executeCrossBorrowERC20(InputTypes.ExecuteCrossBorrowERC20Params memory params) internal returns (uint256) {
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();
    address priceOracle = IAddressProvider(ps.addressProvider).getPriceOracle();

    DataTypes.PoolData storage poolData = ps.poolLookup[params.poolId];
    DataTypes.AssetData storage assetData = poolData.assetLookup[params.asset];

-   // check the basic params
-   ValidateLogic.validateCrossBorrowERC20Basic(params, poolData, assetData);

    // account status need latest balance, update supply & borrow index first
    InterestLogic.updateInterestIndexs(poolData, assetData);

+   // check the basic params
+   ValidateLogic.validateCrossBorrowERC20Basic(params, poolData, assetData);

```
## [L-03] isolate auction process, token blacklisted users may block the bidding process
Currently during the isolate auction process
1. `executeIsolateAuction()` Returns funds from the previous auction to `oldLastBidder` when there is a new bid.
```solidity
      if ((vars.oldLastBidder ! = address(0)) && (vars.oldBidAmount > 0)) {
        VaultLogic.erc20TransferOutBidAmount(debtAssetData, vars.oldLastBidder, vars.oldBidAmount);
      }
```

2. executeIsolateRedeem() has a similar operation
```solidity
      if (loanData.lastBidder ! = address(0)) {
        // transfer last bid from escrow to bidder
        VaultLogic.erc20TransferOutBidAmount(debtAssetData, loanData.lastBidder, loanData.bidAmount);
      }
```

This creates a situation where if `lastBidder` is in the blacklist of `debtAsset`, e.g. `usdc`

This will block the whole bidding process

Suggestion:
If `erc20TransferOutBidAmount()` fails, then try to `claims[token][user]+=bidAmount`
After that it's up to the user to `claims()` on their own initiative


## [L-04] executeIsolateLiquidate() need to add `maxDebtToLiquidate` limit to avoid paying more debt than expected
when execute `executeIsolateLiquidate()`
`msgSender` needs to pay `vars.actualDebtToLiquidate` is calculated by `_calculateDebtAmountFromERC721Collateral()`
```solidity
  function executeCrossLiquidateERC721(
...
    (vars.actualCollateralToLiquidate, vars.actualDebtToLiquidate) = _calculateDebtAmountFromERC721Collateral(
      collateralAssetData,
      debtAssetData,
      params,
      vars,
      IPriceOracleGetter(vars.priceOracle)
    );
@>  VaultLogic.erc20TransferInLiquidity(debtAssetData, params.msgSender, vars.actualDebtToLiquidate);


  function _calculateDebtAmountFromERC721Collateral(
...
    vars.collateralTotalDebtToCover =
@>    (liqVars.userAccountResult.inputCollateralInBaseCurrency * liqVars.userAccountResult.totalDebtInBaseCurrency) /
      liqVars.userAccountResult.totalCollateralInBaseCurrency;
    vars.collateralItemDebtToCover = vars.collateralTotalDebtToCover / liqVars.userCollateralBalance;

```
`vars.actualDebtToLiquidate` is dynamically calculated and may exceed the user's expectations and pay too much funds

Suggestion:
Add `maxDebtToLiquidate` to represent the maximum amount of funds the user is willing to pay
```diff
  function executeCrossLiquidateERC721(
    InputTypes.ExecuteCrossLiquidateERC721Params memory params
  ) internal returns (uint256, uint256) {
...
    (vars.actualCollateralToLiquidate, vars.actualDebtToLiquidate) = _calculateDebtAmountFromERC721Collateral(
      collateralAssetData,
      debtAssetData,
      params,
      vars,
      IPriceOracleGetter(vars.priceOracle)
    );
    require(vars.actualCollateralToLiquidate > 0, Errors.ACTUAL_COLLATERAL_TO_LIQUIDATE_ZERO);
    require(vars.actualDebtToLiquidate > 0, Errors.ACTUAL_DEBT_TO_LIQUIDATE_ZERO);
+   require(vars.actualDebtToLiquidate <=  params.maxDebtToLiquidate, "actualDebtToLiquidate too much );
```


## [L-05] The supplyCap limit may be subject to a DOS attack used to maliciously prevent users from depositing collateral, leading to liquidation
When a user makes a deposit, we check that the `supplyCap` cannot be exceeded.
```solidity
  function validateDepositERC20(
    InputTypes.ExecuteDepositERC20Params memory inputParams,
    DataTypes.PoolData storage poolData,
    DataTypes.AssetData storage assetData
  ) internal view {
...
    if (assetData.supplyCap != 0) {
      uint256 totalScaledSupply = VaultLogic.erc20GetTotalScaledCrossSupply(assetData);
      uint256 totalSupplyWithFee = (totalScaledSupply + assetData.accruedFee).rayMul(assetData.supplyIndex);
@>    require((inputParams.amount + totalSupplyWithFee) <= assetData.supplyCap, Errors.ASSET_SUPPLY_CAP_EXCEEDED);
    }
  }
```

At the same time, this creates a problem: it can be subject to a DOS attack, which can be used to deposit large amounts of funds maliciously, preventing the user from adding further collateral and leading to liquidation.

Suggestion:
Exceed `supplyCap` but user's `healthFactor` is allowed to deposit within a reasonable range, e.g. `healthFactor < 1.1e18`.


## [L-06] erc721TransferIsolateSupplyOnLiquidate() Missing cancel delegate.
when execute `erc721TransferIsolateSupplyOnLiquidate()`
switches `nft owner`.
```solidity
  function erc721TransferIsolateSupplyOnLiquidate(
    DataTypes.AssetData storage assetData,
    address to,
    uint256[] memory tokenIds
  ) internal {
    for (uint256 i = 0; i < tokenIds.length; i++) {
      DataTypes.ERC721TokenData storage tokenData = assetData.erc721TokenData[tokenIds[i]];
      require(tokenData.supplyMode == Constants.SUPPLY_MODE_ISOLATE, Errors.INVALID_SUPPLY_MODE);

      assetData.userScaledIsolateSupply[tokenData.owner] -= 1;
      assetData.userScaledIsolateSupply[to] += 1;
@>    tokenData.owner = to;
    }
  }
```

However, NFTs that have already executed delegate do not cancel them, which does not make sense!

recommendation:
```diff
  function erc721TransferIsolateSupplyOnLiquidate(
    DataTypes.AssetData storage assetData,
    address to,
    uint256[] memory tokenIds
  ) internal {
    for (uint256 i = 0; i < tokenIds.length; i++) {
      DataTypes.ERC721TokenData storage tokenData = assetData.erc721TokenData[tokenIds[i]];
      require(tokenData.supplyMode == Constants.SUPPLY_MODE_ISOLATE, Errors.INVALID_SUPPLY_MODE);

      assetData.userScaledIsolateSupply[tokenData.owner] -= 1;
      assetData.userScaledIsolateSupply[to] += 1;
      tokenData.owner = to;
+     delegateRegistryV2.delegateERC721(address(0)...)
    }
  }
```
