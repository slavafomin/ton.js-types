/**
 * This is a root namespace for TonLib type definitions.
 * Source TonLib schema version is "2".
 */
export namespace TonLib {
  export namespace Types {
    export type AccountAddress = Combinators.AccountAddress
    export type AccountList = Combinators.AccountList
    export type AccountRevisionList = Combinators.AccountRevisionList
    export type AccountState = (
      | Combinators.Raw.AccountState
      | Combinators.Wallet.V3.AccountState
      | Combinators.Wallet.Highload.V1.AccountState
      | Combinators.Wallet.Highload.V2.AccountState
      | Combinators.Dns.AccountState
      | Combinators.Rwallet.AccountState
      | Combinators.Pchan.AccountState
      | Combinators.Uninited.AccountState
    );
    export type Action = (
      | Combinators.ActionNoop
      | Combinators.ActionMsg
      | Combinators.ActionDns
      | Combinators.ActionPchan
      | Combinators.ActionRwallet
    );
    export type AdnlAddress = Combinators.AdnlAddress
    export type Bip39Hints = Combinators.Bip39Hints
    export type Config = Combinators.Config
    export type Data = Combinators.Data
    export type Error = Combinators.Error
    export type ExportedEncryptedKey = Combinators.ExportedEncryptedKey
    export type ExportedKey = Combinators.ExportedKey
    export type ExportedPemKey = Combinators.ExportedPemKey
    export type ExportedUnencryptedKey = (
      | Combinators.ExportedUnencryptedKey
    );
    export type Fees = Combinators.Fees
    export type FullAccountState = Combinators.FullAccountState
    export type InitialAccountState = (
      | Combinators.Raw.InitialAccountState
      | Combinators.Wallet.V3.InitialAccountState
      | Combinators.Wallet.Highload.V1.InitialAccountState
      | Combinators.Wallet.Highload.V2.InitialAccountState
      | Combinators.Rwallet.InitialAccountState
      | Combinators.Dns.InitialAccountState
      | Combinators.Pchan.InitialAccountState
    );
    export type InputKey = (
      | Combinators.InputKeyRegular
      | Combinators.InputKeyFake
    );
    export type Key = Combinators.Key
    export type KeyStoreType = (
      | Combinators.KeyStoreTypeDirectory
      | Combinators.KeyStoreTypeInMemory
    );
    export type LogStream = (
      | Combinators.LogStreamDefault
      | Combinators.LogStreamFile
      | Combinators.LogStreamEmpty
    );
    export type LogTags = Combinators.LogTags
    export type LogVerbosityLevel = Combinators.LogVerbosityLevel
    export type Ok = Combinators.Ok
    export type Options = Combinators.Options
    export type SyncState = (
      | Combinators.SyncStateDone
      | Combinators.SyncStateInProgress
    );
    export type UnpackedAccountAddress = (
      | Combinators.UnpackedAccountAddress
    );
    export type Update = (
      | Combinators.UpdateSendLiteServerQuery
      | Combinators.UpdateSyncState
    );
    export namespace Blocks {
      export type AccountTransactionId = (
        | Combinators.Blocks.AccountTransactionId
      );
      export type Header = Combinators.Blocks.Header
      export type MasterchainInfo = Combinators.Blocks.MasterchainInfo
      export type Shards = Combinators.Blocks.Shards
      export type Transactions = Combinators.Blocks.Transactions
    }
    
    export namespace Dns {
      export type Action = (
        | Combinators.Dns.ActionDeleteAll
        | Combinators.Dns.ActionDelete
        | Combinators.Dns.ActionSet
      );
      export type Entry = Combinators.Dns.Entry
      export type EntryData = (
        | Combinators.Dns.EntryDataUnknown
        | Combinators.Dns.EntryDataText
        | Combinators.Dns.EntryDataNextResolver
        | Combinators.Dns.EntryDataSmcAddress
        | Combinators.Dns.EntryDataAdnlAddress
      );
      export type Resolved = Combinators.Dns.Resolved
    }
    
    export namespace Internal {
      export type BlockId = Combinators.Ton.BlockId
      export type TransactionId = Combinators.Internal.TransactionId
    }
    
    export namespace LiteServer {
      export type Info = Combinators.LiteServer.Info
      export type TransactionId = Combinators.Blocks.ShortTxId
    }
    
    export namespace Msg {
      export type Data = (
        | Combinators.Msg.DataRaw
        | Combinators.Msg.DataText
        | Combinators.Msg.DataDecryptedText
        | Combinators.Msg.DataEncryptedText
      );
      export type DataDecrypted = Combinators.Msg.DataDecrypted
      export type DataDecryptedArray = (
        | Combinators.Msg.DataDecryptedArray
      );
      export type DataEncrypted = Combinators.Msg.DataEncrypted
      export type DataEncryptedArray = (
        | Combinators.Msg.DataEncryptedArray
      );
      export type Message = Combinators.Msg.Message
    }
    
    export namespace Options {
      export type ConfigInfo = Combinators.Options.ConfigInfo
      export type Info = Combinators.Options.Info
    }
    
    export namespace Pchan {
      export type Action = (
        | Combinators.Pchan.ActionInit
        | Combinators.Pchan.ActionClose
        | Combinators.Pchan.ActionTimeout
      );
      export type Config = Combinators.Pchan.Config
      export type Promise = Combinators.Pchan.Promise
      export type State = (
        | Combinators.Pchan.StateInit
        | Combinators.Pchan.StateClose
        | Combinators.Pchan.StatePayout
      );
    }
    
    export namespace Query {
      export type Fees = Combinators.Query.Fees
      export type Info = Combinators.Query.Info
    }
    
    export namespace Raw {
      export type FullAccountState = Combinators.Raw.FullAccountState
      export type Message = Combinators.Raw.Message
      export type Transaction = Combinators.Raw.Transaction
      export type Transactions = Combinators.Raw.Transactions
    }
    
    export namespace Rwallet {
      export type Action = Combinators.Rwallet.ActionInit
      export type Config = Combinators.Rwallet.Config
      export type Limit = Combinators.Rwallet.Limit
    }
    
    export namespace Smc {
      export type Info = Combinators.Smc.Info
      export type MethodId = (
        | Combinators.Smc.MethodIdNumber
        | Combinators.Smc.MethodIdName
      );
      export type RunResult = Combinators.Smc.RunResult
    }
    
    export namespace Ton {
      export type BlockIdExt = Combinators.Ton.BlockIdExt
    }
    
    export namespace Tvm {
      export type Cell = Combinators.Tvm.Cell
      export type List = Combinators.Tvm.List
      export type Number = Combinators.Tvm.NumberDecimal
      export type Slice = Combinators.Tvm.Slice
      export type StackEntry = (
        | Combinators.Tvm.StackEntrySlice
        | Combinators.Tvm.StackEntryCell
        | Combinators.Tvm.StackEntryNumber
        | Combinators.Tvm.StackEntryTuple
        | Combinators.Tvm.StackEntryList
        | Combinators.Tvm.StackEntryUnsupported
      );
      export type Tuple = Combinators.Tvm.Tuple
    }
  }
  
  export namespace Combinators {
    export interface Type<T>{
      '@type': T;
    }
    export interface AccountAddress extends Type<'accountAddress'>{
      account_address: string;
    }
    export interface AccountList extends Type<'accountList'>{
      accounts: (Types.FullAccountState)[];
    }
    export interface AccountRevisionList extends Type<'accountRevisionList'>{
      revisions: (Types.FullAccountState)[];
    }
    export interface ActionNoop extends Type<'actionNoop'>{
    }
    export interface ActionMsg extends Type<'actionMsg'>{
      messages: (Types.Msg.Message)[];
      allow_send_to_uninited: boolean;
    }
    export interface ActionDns extends Type<'actionDns'>{
      actions: (Types.Dns.Action)[];
    }
    export interface ActionPchan extends Type<'actionPchan'>{
      action: Types.Pchan.Action;
    }
    export interface ActionRwallet extends Type<'actionRwallet'>{
      action: Types.Rwallet.Action;
    }
    export interface AdnlAddress extends Type<'adnlAddress'>{
      adnl_address: string;
    }
    export interface Bip39Hints extends Type<'bip39Hints'>{
      words: (string)[];
    }
    export interface Config extends Type<'config'>{
      config: string;
      blockchain_name: string;
      use_callbacks_for_network: boolean;
      ignore_cache: boolean;
    }
    export interface Data extends Type<'data'>{
      bytes: string;
    }
    export interface Error extends Type<'error'>{
      code: number;
      message: string;
    }
    export interface ExportedEncryptedKey extends Type<'exportedEncryptedKey'>{
      data: string;
    }
    export interface ExportedKey extends Type<'exportedKey'>{
      word_list: (string)[];
    }
    export interface ExportedPemKey extends Type<'exportedPemKey'>{
      pem: string;
    }
    export interface ExportedUnencryptedKey extends Type<'exportedUnencryptedKey'>{
      data: string;
    }
    export interface Fees extends Type<'fees'>{
      in_fwd_fee: number;
      storage_fee: number;
      gas_fee: number;
      fwd_fee: number;
    }
    export interface FullAccountState extends Type<'fullAccountState'>{
      address: Types.AccountAddress;
      balance: number;
      last_transaction_id: Types.Internal.TransactionId;
      block_id: Types.Ton.BlockIdExt;
      sync_utime: number;
      account_state: Types.AccountState;
      revision: number;
    }
    export interface InputKeyRegular extends Type<'inputKeyRegular'>{
      key: Types.Key;
      local_password: string;
    }
    export interface InputKeyFake extends Type<'inputKeyFake'>{
    }
    export interface Key extends Type<'key'>{
      public_key: string;
      secret: string;
    }
    export interface KeyStoreTypeDirectory extends Type<'keyStoreTypeDirectory'>{
      directory: string;
    }
    export interface KeyStoreTypeInMemory extends Type<'keyStoreTypeInMemory'>{
    }
    export interface LogStreamDefault extends Type<'logStreamDefault'>{
    }
    export interface LogStreamFile extends Type<'logStreamFile'>{
      path: string;
      max_file_size: number;
    }
    export interface LogStreamEmpty extends Type<'logStreamEmpty'>{
    }
    export interface LogTags extends Type<'logTags'>{
      tags: (string)[];
    }
    export interface LogVerbosityLevel extends Type<'logVerbosityLevel'>{
      verbosity_level: number;
    }
    export interface Ok extends Type<'ok'>{
    }
    export interface Options extends Type<'options'>{
      config: Types.Config;
      keystore_type: Types.KeyStoreType;
    }
    export interface SyncStateDone extends Type<'syncStateDone'>{
    }
    export interface SyncStateInProgress extends Type<'syncStateInProgress'>{
      from_seqno: number;
      to_seqno: number;
      current_seqno: number;
    }
    export interface UnpackedAccountAddress extends Type<'unpackedAccountAddress'>{
      workchain_id: number;
      bounceable: boolean;
      testnet: boolean;
      addr: string;
    }
    export interface UpdateSendLiteServerQuery extends Type<'updateSendLiteServerQuery'>{
      id: number;
      data: string;
    }
    export interface UpdateSyncState extends Type<'updateSyncState'>{
      sync_state: Types.SyncState;
    }
    export interface AddLogMessage extends Type<'addLogMessage'>{
      verbosity_level: number;
      text: string;
    }
    export interface ChangeLocalPassword extends Type<'changeLocalPassword'>{
      input_key: Types.InputKey;
      new_local_password: string;
    }
    export interface Close extends Type<'close'>{
    }
    export interface CreateNewKey extends Type<'createNewKey'>{
      local_password: string;
      mnemonic_password: string;
      random_extra_seed: string;
    }
    export interface CreateQuery extends Type<'createQuery'>{
      private_key: Types.InputKey;
      address: Types.AccountAddress;
      timeout: number;
      action: Types.Action;
      initial_account_state: Types.InitialAccountState;
    }
    export interface Decrypt extends Type<'decrypt'>{
      encrypted_data: string;
      secret: string;
    }
    export interface DeleteAllKeys extends Type<'deleteAllKeys'>{
    }
    export interface DeleteKey extends Type<'deleteKey'>{
      key: Types.Key;
    }
    export interface Encrypt extends Type<'encrypt'>{
      decrypted_data: string;
      secret: string;
    }
    export interface ExportEncryptedKey extends Type<'exportEncryptedKey'>{
      input_key: Types.InputKey;
      key_password: string;
    }
    export interface ExportKey extends Type<'exportKey'>{
      input_key: Types.InputKey;
    }
    export interface ExportPemKey extends Type<'exportPemKey'>{
      input_key: Types.InputKey;
      key_password: string;
    }
    export interface ExportUnencryptedKey extends Type<'exportUnencryptedKey'>{
      input_key: Types.InputKey;
    }
    export interface GetAccountAddress extends Type<'getAccountAddress'>{
      initial_account_state: Types.InitialAccountState;
      revision: number;
      workchain_id: number;
    }
    export interface GetAccountState extends Type<'getAccountState'>{
      account_address: Types.AccountAddress;
    }
    export interface GetBip39Hints extends Type<'getBip39Hints'>{
      prefix: string;
    }
    export interface GetLogStream extends Type<'getLogStream'>{
    }
    export interface GetLogTagVerbosityLevel extends Type<'getLogTagVerbosityLevel'>{
      tag: string;
    }
    export interface GetLogTags extends Type<'getLogTags'>{
    }
    export interface GetLogVerbosityLevel extends Type<'getLogVerbosityLevel'>{
    }
    export interface GuessAccount extends Type<'guessAccount'>{
      public_key: string;
      rwallet_init_public_key: string;
    }
    export interface GuessAccountRevision extends Type<'guessAccountRevision'>{
      initial_account_state: Types.InitialAccountState;
      workchain_id: number;
    }
    export interface ImportEncryptedKey extends Type<'importEncryptedKey'>{
      local_password: string;
      key_password: string;
      exported_encrypted_key: Types.ExportedEncryptedKey;
    }
    export interface ImportKey extends Type<'importKey'>{
      local_password: string;
      mnemonic_password: string;
      exported_key: Types.ExportedKey;
    }
    export interface ImportPemKey extends Type<'importPemKey'>{
      local_password: string;
      key_password: string;
      exported_key: Types.ExportedPemKey;
    }
    export interface ImportUnencryptedKey extends Type<'importUnencryptedKey'>{
      local_password: string;
      exported_unencrypted_key: Types.ExportedUnencryptedKey;
    }
    export interface Init extends Type<'init'>{
      options: Types.Options;
    }
    export interface Kdf extends Type<'kdf'>{
      password: string;
      salt: string;
      iterations: number;
    }
    export interface OnLiteServerQueryError extends Type<'onLiteServerQueryError'>{
      id: number;
      error: Types.Error;
    }
    export interface OnLiteServerQueryResult extends Type<'onLiteServerQueryResult'>{
      id: number;
      bytes: string;
    }
    export interface PackAccountAddress extends Type<'packAccountAddress'>{
      account_address: Types.UnpackedAccountAddress;
    }
    export interface RunTests extends Type<'runTests'>{
      dir: string;
    }
    export interface SetLogStream extends Type<'setLogStream'>{
      log_stream: Types.LogStream;
    }
    export interface SetLogTagVerbosityLevel extends Type<'setLogTagVerbosityLevel'>{
      tag: string;
      new_verbosity_level: number;
    }
    export interface SetLogVerbosityLevel extends Type<'setLogVerbosityLevel'>{
      new_verbosity_level: number;
    }
    export interface Sync extends Type<'sync'>{
    }
    export interface UnpackAccountAddress extends Type<'unpackAccountAddress'>{
      account_address: string;
    }
    export interface WithBlock extends Type<'withBlock'>{
      id: Types.Ton.BlockIdExt;
      function: unknown;
    }
    export namespace Raw {
      export interface AccountState extends Type<'raw.accountState'>{
        code: string;
        data: string;
        frozen_hash: string;
      }
      export interface InitialAccountState extends Type<'raw.initialAccountState'>{
        code: string;
        data: string;
      }
      export interface FullAccountState extends Type<'raw.fullAccountState'>{
        balance: number;
        code: string;
        data: string;
        last_transaction_id: Types.Internal.TransactionId;
        block_id: Types.Ton.BlockIdExt;
        frozen_hash: string;
        sync_utime: number;
      }
      export interface Message extends Type<'raw.message'>{
        source: Types.AccountAddress;
        destination: Types.AccountAddress;
        value: number;
        fwd_fee: number;
        ihr_fee: number;
        created_lt: number;
        body_hash: string;
        msg_data: Types.Msg.Data;
      }
      export interface Transaction extends Type<'raw.transaction'>{
        utime: number;
        data: string;
        transaction_id: Types.Internal.TransactionId;
        fee: number;
        storage_fee: number;
        other_fee: number;
        in_msg: Types.Raw.Message;
        out_msgs: (Types.Raw.Message)[];
      }
      export interface Transactions extends Type<'raw.transactions'>{
        transactions: (Types.Raw.Transaction)[];
        previous_transaction_id: Types.Internal.TransactionId;
      }
      export interface CreateAndSendMessage extends Type<'raw.createAndSendMessage'>{
        destination: Types.AccountAddress;
        initial_account_state: string;
        data: string;
      }
      export interface CreateQuery extends Type<'raw.createQuery'>{
        destination: Types.AccountAddress;
        init_code: string;
        init_data: string;
        body: string;
      }
      export interface GetAccountState extends Type<'raw.getAccountState'>{
        account_address: Types.AccountAddress;
      }
      export interface GetTransactions extends Type<'raw.getTransactions'>{
        private_key: Types.InputKey;
        account_address: Types.AccountAddress;
        from_transaction_id: Types.Internal.TransactionId;
      }
      export interface SendMessage extends Type<'raw.sendMessage'>{
        body: string;
      }
    }
    
    export namespace Wallet {
      export namespace V3 {
        export interface AccountState extends Type<'wallet.v3.accountState'>{
          wallet_id: number;
          seqno: number;
        }
        export interface InitialAccountState extends Type<'wallet.v3.initialAccountState'>{
          public_key: string;
          wallet_id: number;
        }
      }
      
      export namespace Highload {
        export namespace V1 {
          export interface AccountState extends Type<'wallet.highload.v1.accountState'>{
            wallet_id: number;
            seqno: number;
          }
          export interface InitialAccountState extends Type<'wallet.highload.v1.initialAccountState'>{
            public_key: string;
            wallet_id: number;
          }
        }
        
        export namespace V2 {
          export interface AccountState extends Type<'wallet.highload.v2.accountState'>{
            wallet_id: number;
          }
          export interface InitialAccountState extends Type<'wallet.highload.v2.initialAccountState'>{
            public_key: string;
            wallet_id: number;
          }
        }
      }
    }
    
    export namespace Dns {
      export interface AccountState extends Type<'dns.accountState'>{
        wallet_id: number;
      }
      export interface InitialAccountState extends Type<'dns.initialAccountState'>{
        public_key: string;
        wallet_id: number;
      }
      export interface ActionDeleteAll extends Type<'dns.actionDeleteAll'>{
      }
      export interface ActionDelete extends Type<'dns.actionDelete'>{
        name: string;
        category: number;
      }
      export interface ActionSet extends Type<'dns.actionSet'>{
        entry: Types.Dns.Entry;
      }
      export interface Entry extends Type<'dns.entry'>{
        name: string;
        category: number;
        entry: Types.Dns.EntryData;
      }
      export interface EntryDataUnknown extends Type<'dns.entryDataUnknown'>{
        bytes: string;
      }
      export interface EntryDataText extends Type<'dns.entryDataText'>{
        text: string;
      }
      export interface EntryDataNextResolver extends Type<'dns.entryDataNextResolver'>{
        resolver: Types.AccountAddress;
      }
      export interface EntryDataSmcAddress extends Type<'dns.entryDataSmcAddress'>{
        smc_address: Types.AccountAddress;
      }
      export interface EntryDataAdnlAddress extends Type<'dns.entryDataAdnlAddress'>{
        adnl_address: Types.AdnlAddress;
      }
      export interface Resolved extends Type<'dns.resolved'>{
        entries: (Types.Dns.Entry)[];
      }
      export interface Resolve extends Type<'dns.resolve'>{
        account_address: Types.AccountAddress;
        name: string;
        category: number;
        ttl: number;
      }
    }
    
    export namespace Rwallet {
      export interface AccountState extends Type<'rwallet.accountState'>{
        wallet_id: number;
        seqno: number;
        unlocked_balance: number;
        config: Types.Rwallet.Config;
      }
      export interface InitialAccountState extends Type<'rwallet.initialAccountState'>{
        init_public_key: string;
        public_key: string;
        wallet_id: number;
      }
      export interface ActionInit extends Type<'rwallet.actionInit'>{
        config: Types.Rwallet.Config;
      }
      export interface Config extends Type<'rwallet.config'>{
        start_at: number;
        limits: (Types.Rwallet.Limit)[];
      }
      export interface Limit extends Type<'rwallet.limit'>{
        seconds: number;
        value: number;
      }
    }
    
    export namespace Pchan {
      export interface AccountState extends Type<'pchan.accountState'>{
        config: Types.Pchan.Config;
        state: Types.Pchan.State;
        description: string;
      }
      export interface InitialAccountState extends Type<'pchan.initialAccountState'>{
        config: Types.Pchan.Config;
      }
      export interface ActionInit extends Type<'pchan.actionInit'>{
        inc_A: number;
        inc_B: number;
        min_A: number;
        min_B: number;
      }
      export interface ActionClose extends Type<'pchan.actionClose'>{
        extra_A: number;
        extra_B: number;
        promise: Types.Pchan.Promise;
      }
      export interface ActionTimeout extends Type<'pchan.actionTimeout'>{
      }
      export interface Config extends Type<'pchan.config'>{
        alice_public_key: string;
        alice_address: Types.AccountAddress;
        bob_public_key: string;
        bob_address: Types.AccountAddress;
        init_timeout: number;
        close_timeout: number;
        channel_id: number;
      }
      export interface Promise extends Type<'pchan.promise'>{
        signature: string;
        promise_A: number;
        promise_B: number;
        channel_id: number;
      }
      export interface StateInit extends Type<'pchan.stateInit'>{
        signed_A: boolean;
        signed_B: boolean;
        min_A: number;
        min_B: number;
        expire_at: number;
        A: number;
        B: number;
      }
      export interface StateClose extends Type<'pchan.stateClose'>{
        signed_A: boolean;
        signed_B: boolean;
        min_A: number;
        min_B: number;
        expire_at: number;
        A: number;
        B: number;
      }
      export interface StatePayout extends Type<'pchan.statePayout'>{
        A: number;
        B: number;
      }
      export interface PackPromise extends Type<'pchan.packPromise'>{
        promise: Types.Pchan.Promise;
      }
      export interface SignPromise extends Type<'pchan.signPromise'>{
        input_key: Types.InputKey;
        promise: Types.Pchan.Promise;
      }
      export interface UnpackPromise extends Type<'pchan.unpackPromise'>{
        data: string;
      }
      export interface ValidatePromise extends Type<'pchan.validatePromise'>{
        public_key: string;
        promise: Types.Pchan.Promise;
      }
    }
    
    export namespace Uninited {
      export interface AccountState extends Type<'uninited.accountState'>{
        frozen_hash: string;
      }
    }
    
    export namespace Blocks {
      export interface AccountTransactionId extends Type<'blocks.accountTransactionId'>{
        account: string;
        lt: number;
      }
      export interface Header extends Type<'blocks.header'>{
        id: Types.Ton.BlockIdExt;
        global_id: number;
        version: number;
        after_merge: boolean;
        after_split: boolean;
        before_split: boolean;
        want_merge: boolean;
        want_split: boolean;
        validator_list_hash_short: number;
        catchain_seqno: number;
        min_ref_mc_seqno: number;
        is_key_block: boolean;
        prev_key_block_seqno: number;
        start_lt: number;
        end_lt: number;
        vert_seqno: number;
        prev_blocks: (Types.Ton.BlockIdExt)[];
      }
      export interface MasterchainInfo extends Type<'blocks.masterchainInfo'>{
        last: Types.Ton.BlockIdExt;
        state_root_hash: string;
        init: Types.Ton.BlockIdExt;
      }
      export interface Shards extends Type<'blocks.shards'>{
        shards: (Types.Ton.BlockIdExt)[];
      }
      export interface Transactions extends Type<'blocks.transactions'>{
        id: Types.Ton.BlockIdExt;
        req_count: number;
        incomplete: boolean;
        transactions: (Types.LiteServer.TransactionId)[];
      }
      export interface ShortTxId extends Type<'blocks.shortTxId'>{
        mode: number;
        account: string;
        lt: number;
        hash: string;
      }
      export interface GetBlockHeader extends Type<'blocks.getBlockHeader'>{
        id: Types.Ton.BlockIdExt;
      }
      export interface GetMasterchainInfo extends Type<'blocks.getMasterchainInfo'>{
      }
      export interface GetShards extends Type<'blocks.getShards'>{
        id: Types.Ton.BlockIdExt;
      }
      export interface GetTransactions extends Type<'blocks.getTransactions'>{
        id: Types.Ton.BlockIdExt;
        mode: number;
        count: number;
        after: Types.Blocks.AccountTransactionId;
      }
      export interface LookupBlock extends Type<'blocks.lookupBlock'>{
        mode: number;
        id: Types.Internal.BlockId;
        lt: number;
        utime: number;
      }
    }
    
    export namespace Ton {
      export interface BlockId extends Type<'ton.blockId'>{
        workchain: number;
        shard: number;
        seqno: number;
      }
      export interface BlockIdExt extends Type<'ton.blockIdExt'>{
        workchain: number;
        shard: number;
        seqno: number;
        root_hash: string;
        file_hash: string;
      }
    }
    
    export namespace Internal {
      export interface TransactionId extends Type<'internal.transactionId'>{
        lt: number;
        hash: string;
      }
    }
    
    export namespace LiteServer {
      export interface Info extends Type<'liteServer.info'>{
        now: number;
        version: number;
        capabilities: number;
      }
      export interface GetInfo extends Type<'liteServer.getInfo'>{
      }
    }
    
    export namespace Msg {
      export interface DataRaw extends Type<'msg.dataRaw'>{
        body: string;
        init_state: string;
      }
      export interface DataText extends Type<'msg.dataText'>{
        text: string;
      }
      export interface DataDecryptedText extends Type<'msg.dataDecryptedText'>{
        text: string;
      }
      export interface DataEncryptedText extends Type<'msg.dataEncryptedText'>{
        text: string;
      }
      export interface DataDecrypted extends Type<'msg.dataDecrypted'>{
        proof: string;
        data: Types.Msg.Data;
      }
      export interface DataDecryptedArray extends Type<'msg.dataDecryptedArray'>{
        elements: (Types.Msg.DataDecrypted)[];
      }
      export interface DataEncrypted extends Type<'msg.dataEncrypted'>{
        source: Types.AccountAddress;
        data: Types.Msg.Data;
      }
      export interface DataEncryptedArray extends Type<'msg.dataEncryptedArray'>{
        elements: (Types.Msg.DataEncrypted)[];
      }
      export interface Message extends Type<'msg.message'>{
        destination: Types.AccountAddress;
        public_key: string;
        amount: number;
        data: Types.Msg.Data;
        send_mode: number;
      }
      export interface Decrypt extends Type<'msg.decrypt'>{
        input_key: Types.InputKey;
        data: Types.Msg.DataEncryptedArray;
      }
      export interface DecryptWithProof extends Type<'msg.decryptWithProof'>{
        proof: string;
        data: Types.Msg.DataEncrypted;
      }
    }
    
    export namespace Options {
      export interface ConfigInfo extends Type<'options.configInfo'>{
        default_wallet_id: number;
        default_rwallet_init_public_key: string;
      }
      export interface Info extends Type<'options.info'>{
        config_info: Types.Options.ConfigInfo;
      }
      export interface SetConfig extends Type<'options.setConfig'>{
        config: Types.Config;
      }
      export interface ValidateConfig extends Type<'options.validateConfig'>{
        config: Types.Config;
      }
    }
    
    export namespace Query {
      export interface Fees extends Type<'query.fees'>{
        source_fees: Types.Fees;
        destination_fees: (Types.Fees)[];
      }
      export interface Info extends Type<'query.info'>{
        id: number;
        valid_until: number;
        body_hash: string;
        body: string;
        init_state: string;
      }
      export interface EstimateFees extends Type<'query.estimateFees'>{
        id: number;
        ignore_chksig: boolean;
      }
      export interface Forget extends Type<'query.forget'>{
        id: number;
      }
      export interface GetInfo extends Type<'query.getInfo'>{
        id: number;
      }
      export interface Send extends Type<'query.send'>{
        id: number;
      }
    }
    
    export namespace Smc {
      export interface Info extends Type<'smc.info'>{
        id: number;
      }
      export interface MethodIdNumber extends Type<'smc.methodIdNumber'>{
        number: number;
      }
      export interface MethodIdName extends Type<'smc.methodIdName'>{
        name: string;
      }
      export interface RunResult extends Type<'smc.runResult'>{
        gas_used: number;
        stack: (Types.Tvm.StackEntry)[];
        exit_code: number;
      }
      export interface GetCode extends Type<'smc.getCode'>{
        id: number;
      }
      export interface GetData extends Type<'smc.getData'>{
        id: number;
      }
      export interface GetState extends Type<'smc.getState'>{
        id: number;
      }
      export interface Load extends Type<'smc.load'>{
        account_address: Types.AccountAddress;
      }
      export interface RunGetMethod extends Type<'smc.runGetMethod'>{
        id: number;
        method: Types.Smc.MethodId;
        stack: (Types.Tvm.StackEntry)[];
      }
    }
    
    export namespace Tvm {
      export interface Cell extends Type<'tvm.cell'>{
        bytes: string;
      }
      export interface List extends Type<'tvm.list'>{
        elements: (Types.Tvm.StackEntry)[];
      }
      export interface NumberDecimal extends Type<'tvm.numberDecimal'>{
        number: string;
      }
      export interface Slice extends Type<'tvm.slice'>{
        bytes: string;
      }
      export interface StackEntrySlice extends Type<'tvm.stackEntrySlice'>{
        slice: Types.Tvm.Slice;
      }
      export interface StackEntryCell extends Type<'tvm.stackEntryCell'>{
        cell: Types.Tvm.Cell;
      }
      export interface StackEntryNumber extends Type<'tvm.stackEntryNumber'>{
        number: Types.Tvm.Number;
      }
      export interface StackEntryTuple extends Type<'tvm.stackEntryTuple'>{
        tuple: Types.Tvm.Tuple;
      }
      export interface StackEntryList extends Type<'tvm.stackEntryList'>{
        list: Types.Tvm.List;
      }
      export interface StackEntryUnsupported extends Type<'tvm.stackEntryUnsupported'>{
      }
      export interface Tuple extends Type<'tvm.tuple'>{
        elements: (Types.Tvm.StackEntry)[];
      }
    }
  }
}
