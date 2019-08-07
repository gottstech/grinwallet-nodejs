var addon = require('../native');

const {
    grinCheckPassword,
    grinWalletChangePassword,
    grinWalletInit,
    grinWalletInitRecover,
    grinWalletRestore,
    grinWalletCheck,
    grinGetWalletMnemonic,
    grinGetBalance,
    grinTxRetrieve,
    grinTxsRetrieve,
    grinOutputRetrieve,
    grinOutputsRetrieve,
    grinListen,
    grinRelayAddr,
    grinInitTx,
    grinSendTx,
    grinCancelTx,
    grinPostTx,
    grinTxFileReceive,
    grinTxFileFinalize,
    grinChainHeight,
} = addon;

module.exports = addon;