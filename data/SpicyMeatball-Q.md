### It is possible to bypass the asset supply cap
When a liquidator liquidates a position for ERC721 collateral, he should pay off the debt that is covered by NFT tokens, if the calculated debt is greater than the actual borrowers debt, the remainder will be sent to the borrower as a supply:

https://github.com/code-423n4/2024-07-benddao/blob/main/src/libraries/logic/LiquidationLogic.sol#L221

```solidity
  function executeCrossLiquidateERC721(
    InputTypes.ExecuteCrossLiquidateERC721Params memory params
  ) internal returns (uint256, uint256) {
    ---SNIP---

    // the liquidated debt amount will be decided by the liquidated collateral
    (vars.actualCollateralToLiquidate, vars.actualDebtToLiquidate) = _calculateDebtAmountFromERC721Collateral(
      collateralAssetData,
      debtAssetData,
      params,
      vars,
      IPriceOracleGetter(vars.priceOracle)
    );
    require(vars.actualCollateralToLiquidate > 0, Errors.ACTUAL_COLLATERAL_TO_LIQUIDATE_ZERO);
    require(vars.actualDebtToLiquidate > 0, Errors.ACTUAL_DEBT_TO_LIQUIDATE_ZERO);

    // try to repay debt for the user, the liquidated debt amount may less than user total debt
    vars.remainDebtToLiquidate = _repayUserERC20Debt(
      poolData,
      debtAssetData,
      params.borrower,
      vars.actualDebtToLiquidate
    );
    if (vars.remainDebtToLiquidate > 0) {
      // transfer the remain debt asset to the user as new supplied collateral
>>    VaultLogic.erc20IncreaseCrossSupply(debtAssetData, params.borrower, vars.remainDebtToLiquidate);
```
No check is performed that total asset supply will be greater than supply cap.

### It is possible to borrow beyond the asset borrow cap
`executeCrossBorrowERC20` updates interest indexes after a validation in which the protocol verifies that the borrow cap hasn't been reached:

https://github.com/code-423n4/2024-07-benddao/blob/main/src/libraries/logic/ValidateLogic.sol#L206-L218

```solidity
  function validateCrossBorrowERC20Basic(
    InputTypes.ExecuteCrossBorrowERC20Params memory inputParams,
    DataTypes.PoolData storage poolData,
    DataTypes.AssetData storage assetData
  ) internal view {
    ---SNIP--

    if (assetData.borrowCap != 0) {
      vars.totalAssetBorrowAmount =
        VaultLogic.erc20GetTotalCrossBorrowInAsset(assetData) +
        VaultLogic.erc20GetTotalIsolateBorrowInAsset(assetData);

      for (vars.gidx = 0; vars.gidx < inputParams.groups.length; vars.gidx++) {
        vars.totalNewBorrowAmount += inputParams.amounts[vars.gidx];
      }

>>    require(
        (vars.totalAssetBorrowAmount + vars.totalNewBorrowAmount) <= assetData.borrowCap,
        Errors.ASSET_BORROW_CAP_EXCEEDED
      );
    }
  }
```
Therefore old indexes will be used to calculate `totalNewBorrowAmount`, resulting in incorrect amounts being used when checking the borrow cap. Consider updating indexes before validation:

https://github.com/code-423n4/2024-07-benddao/blob/main/src/libraries/logic/BorrowLogic.sol#L23

```diff
  function executeCrossBorrowERC20(InputTypes.ExecuteCrossBorrowERC20Params memory params) internal returns (uint256) {
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();
    address priceOracle = IAddressProvider(ps.addressProvider).getPriceOracle();

    DataTypes.PoolData storage poolData = ps.poolLookup[params.poolId];
    DataTypes.AssetData storage assetData = poolData.assetLookup[params.asset];

+   // account status need latest balance, update supply & borrow index first
+   InterestLogic.updateInterestIndexs(poolData, assetData);

    // check the basic params
    ValidateLogic.validateCrossBorrowERC20Basic(params, poolData, assetData);
```

### Indexes are updated for NFT assets

When calling the `executeCrossLiquidateERC721`, the protocol will update the indexes for the collateral asset:

https://github.com/code-423n4/2024-07-benddao/blob/main/src/libraries/logic/LiquidationLogic.sol#L177

```solidity
  function executeCrossLiquidateERC721(
    InputTypes.ExecuteCrossLiquidateERC721Params memory params
  ) internal returns (uint256, uint256) {
    ---SNIP---

    DataTypes.AssetData storage collateralAssetData = poolData.assetLookup[params.collateralAsset];
    DataTypes.AssetData storage debtAssetData = poolData.assetLookup[params.debtAsset];

    // make sure coallteral asset's all index updated
>>  InterestLogic.updateInterestIndexs(poolData, collateralAssetData);
```

However, NFT assets can't be borrowed and therefore do not collect any interest, so it's safe to remove this function call.

### Assets are incorrectly removed and can't be re-added
When an asset is removed by the `_removeAsset` function, it's data is not deleted, so it's still possible to deposit and borrow. In addition, the admin won't be able to re-add it to the pool again because of the following check:

```solidity
  function executeAddAssetERC20(address msgSender, uint32 poolId, address asset) internal {
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();

    DataTypes.PoolData storage poolData = ps.poolLookup[poolId];
    _validateCallerAndPool(msgSender, ps, poolData);

    DataTypes.AssetData storage assetData = poolData.assetLookup[asset];
>>  require(assetData.assetType == 0, Errors.ASSET_ALREADY_EXISTS);
```  
It is advised to disable the asset and clear the `assetType` on removal.

### Yield registry doesn't use pause

The `YieldRegistry.sol` contract inherits from the `PausableUpgradeable.sol` but doesn't use pausing feature anywhere.

### `WithdrawERC20` might be executed with a partial amount 

```solidity
  function withdrawERC20(
    uint32 poolId,
    address asset,
    uint256 amount,
    address onBehalf,
    address receiver
  ) public whenNotPaused nonReentrant {
    address msgSender = unpackTrailingParamMsgSender();
    DataTypes.PoolStorage storage ps = StorageSlot.getPoolStorage();
    bool isNative;
    if (asset == Constants.NATIVE_TOKEN_ADDRESS) {
      isNative = true;
      asset = ps.wrappedNativeToken;
    }

    SupplyLogic.executeWithdrawERC20(
      InputTypes.ExecuteWithdrawERC20Params({
        msgSender: msgSender,
        poolId: poolId,
        asset: asset,
        amount: amount,
        onBehalf: onBehalf,
        receiver: receiver
      })
    );

    if (isNative) {
>>    VaultLogic.unwrapNativeTokenInWallet(asset, msgSender, amount);
    }
```
When the user withdraws ERC20 asset from the pool he may specify to receive native tokens. However, incorrect amount may be used in the `unwrapNativeTokenInWallet` function, because withdraw can be executed with a partial amount instead of the `amount` that was specified by the user:

https://github.com/code-423n4/2024-07-benddao/blob/main/src/libraries/logic/SupplyLogic.sol#L53

```solidity
    uint256 userBalance = VaultLogic.erc20GetUserCrossSupply(assetData, params.onBehalf, assetData.supplyIndex);
    if (userBalance < params.amount) {
>>    params.amount = userBalance;
    }
```

It is recommended to return an actual withdrawn amount in the `executeWithdrawERC20` function and use it in `unwrapNativeTokenInWallet`.



