/**
 * This is a root namespace for TonLib type definitions.
 * Source TonLib schema version is "2".
 */
export namespace TonLib {
  export namespace Types {
    export type Vector<T> = (T)[];
    export type String = string;
    export type SecureString = string;
    export type SecureBytes = string;
    export type Object = Record<string, unknown>;
    export type Int64 = number;
    export type Int53 = number;
    export type Int32 = number;
    export type Function = unknown;
    export type Double = number;
    export type Bytes = string;
    export type Bool = boolean;
    export type NatConst = number;
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
      account_address: Types.String;
    }
    export interface AccountList extends Type<'accountList'>{
      accounts: Types.Vector<Types.FullAccountState>;
    }
    export interface AccountRevisionList extends Type<'accountRevisionList'>{
      revisions: Types.Vector<Types.FullAccountState>;
    }
    export interface ActionNoop extends Type<'actionNoop'>{
    }
    export interface ActionMsg extends Type<'actionMsg'>{
      messages: Types.Vector<Types.Msg.Message>;
      allow_send_to_uninited: Types.Bool;
    }
    export interface ActionDns extends Type<'actionDns'>{
      actions: Types.Vector<Types.Dns.Action>;
    }
    export interface ActionPchan extends Type<'actionPchan'>{
      action: Types.Pchan.Action;
    }
    export interface ActionRwallet extends Type<'actionRwallet'>{
      action: Types.Rwallet.Action;
    }
    export interface AdnlAddress extends Type<'adnlAddress'>{
      adnl_address: Types.String;
    }
    export interface Bip39Hints extends Type<'bip39Hints'>{
      words: Types.Vector<Types.String>;
    }
    export interface Config extends Type<'config'>{
      config: Types.String;
      blockchain_name: Types.String;
      use_callbacks_for_network: Types.Bool;
      ignore_cache: Types.Bool;
    }
    export interface Data extends Type<'data'>{
      bytes: Types.SecureBytes;
    }
    export interface Error extends Type<'error'>{
      code: Types.Int32;
      message: Types.String;
    }
    export interface ExportedEncryptedKey extends Type<'exportedEncryptedKey'>{
      data: Types.SecureBytes;
    }
    export interface ExportedKey extends Type<'exportedKey'>{
      word_list: Types.Vector<Types.SecureString>;
    }
    export interface ExportedPemKey extends Type<'exportedPemKey'>{
      pem: Types.SecureString;
    }
    export interface ExportedUnencryptedKey extends Type<'exportedUnencryptedKey'>{
      data: Types.SecureBytes;
    }
    export interface Fees extends Type<'fees'>{
      in_fwd_fee: Types.Int53;
      storage_fee: Types.Int53;
      gas_fee: Types.Int53;
      fwd_fee: Types.Int53;
    }
    export interface FullAccountState extends Type<'fullAccountState'>{
      address: Types.AccountAddress;
      balance: Types.Int64;
      last_transaction_id: Types.Internal.TransactionId;
      block_id: Types.Ton.BlockIdExt;
      sync_utime: Types.Int53;
      account_state: Types.AccountState;
      revision: Types.Int32;
    }
    export interface InputKeyRegular extends Type<'inputKeyRegular'>{
      key: Types.Key;
      local_password: Types.SecureBytes;
    }
    export interface InputKeyFake extends Type<'inputKeyFake'>{
    }
    export interface Key extends Type<'key'>{
      public_key: Types.String;
      secret: Types.SecureBytes;
    }
    export interface KeyStoreTypeDirectory extends Type<'keyStoreTypeDirectory'>{
      directory: Types.String;
    }
    export interface KeyStoreTypeInMemory extends Type<'keyStoreTypeInMemory'>{
    }
    export interface LogStreamDefault extends Type<'logStreamDefault'>{
    }
    export interface LogStreamFile extends Type<'logStreamFile'>{
      path: Types.String;
      max_file_size: Types.Int53;
    }
    export interface LogStreamEmpty extends Type<'logStreamEmpty'>{
    }
    export interface LogTags extends Type<'logTags'>{
      tags: Types.Vector<Types.String>;
    }
    export interface LogVerbosityLevel extends Type<'logVerbosityLevel'>{
      verbosity_level: Types.Int32;
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
      from_seqno: Types.Int32;
      to_seqno: Types.Int32;
      current_seqno: Types.Int32;
    }
    export interface UnpackedAccountAddress extends Type<'unpackedAccountAddress'>{
      workchain_id: Types.Int32;
      bounceable: Types.Bool;
      testnet: Types.Bool;
      addr: Types.Bytes;
    }
    export interface UpdateSendLiteServerQuery extends Type<'updateSendLiteServerQuery'>{
      id: Types.Int64;
      data: Types.Bytes;
    }
    export interface UpdateSyncState extends Type<'updateSyncState'>{
      sync_state: Types.SyncState;
    }
    export interface AddLogMessage extends Type<'addLogMessage'>{
      verbosity_level: Types.Int32;
      text: Types.String;
    }
    export interface ChangeLocalPassword extends Type<'changeLocalPassword'>{
      input_key: Types.InputKey;
      new_local_password: Types.SecureBytes;
    }
    export interface Close extends Type<'close'>{
    }
    export interface CreateNewKey extends Type<'createNewKey'>{
      local_password: Types.SecureBytes;
      mnemonic_password: Types.SecureBytes;
      random_extra_seed: Types.SecureBytes;
    }
    export interface CreateQuery extends Type<'createQuery'>{
      private_key: Types.InputKey;
      address: Types.AccountAddress;
      timeout: Types.Int32;
      action: Types.Action;
      initial_account_state: Types.InitialAccountState;
    }
    export interface Decrypt extends Type<'decrypt'>{
      encrypted_data: Types.SecureBytes;
      secret: Types.SecureBytes;
    }
    export interface DeleteAllKeys extends Type<'deleteAllKeys'>{
    }
    export interface DeleteKey extends Type<'deleteKey'>{
      key: Types.Key;
    }
    export interface Encrypt extends Type<'encrypt'>{
      decrypted_data: Types.SecureBytes;
      secret: Types.SecureBytes;
    }
    export interface ExportEncryptedKey extends Type<'exportEncryptedKey'>{
      input_key: Types.InputKey;
      key_password: Types.SecureBytes;
    }
    export interface ExportKey extends Type<'exportKey'>{
      input_key: Types.InputKey;
    }
    export interface ExportPemKey extends Type<'exportPemKey'>{
      input_key: Types.InputKey;
      key_password: Types.SecureBytes;
    }
    export interface ExportUnencryptedKey extends Type<'exportUnencryptedKey'>{
      input_key: Types.InputKey;
    }
    export interface GetAccountAddress extends Type<'getAccountAddress'>{
      initial_account_state: Types.InitialAccountState;
      revision: Types.Int32;
      workchain_id: Types.Int32;
    }
    export interface GetAccountState extends Type<'getAccountState'>{
      account_address: Types.AccountAddress;
    }
    export interface GetBip39Hints extends Type<'getBip39Hints'>{
      prefix: Types.String;
    }
    export interface GetLogStream extends Type<'getLogStream'>{
    }
    export interface GetLogTagVerbosityLevel extends Type<'getLogTagVerbosityLevel'>{
      tag: Types.String;
    }
    export interface GetLogTags extends Type<'getLogTags'>{
    }
    export interface GetLogVerbosityLevel extends Type<'getLogVerbosityLevel'>{
    }
    export interface GuessAccount extends Type<'guessAccount'>{
      public_key: Types.String;
      rwallet_init_public_key: Types.String;
    }
    export interface GuessAccountRevision extends Type<'guessAccountRevision'>{
      initial_account_state: Types.InitialAccountState;
      workchain_id: Types.Int32;
    }
    export interface ImportEncryptedKey extends Type<'importEncryptedKey'>{
      local_password: Types.SecureBytes;
      key_password: Types.SecureBytes;
      exported_encrypted_key: Types.ExportedEncryptedKey;
    }
    export interface ImportKey extends Type<'importKey'>{
      local_password: Types.SecureBytes;
      mnemonic_password: Types.SecureBytes;
      exported_key: Types.ExportedKey;
    }
    export interface ImportPemKey extends Type<'importPemKey'>{
      local_password: Types.SecureBytes;
      key_password: Types.SecureBytes;
      exported_key: Types.ExportedPemKey;
    }
    export interface ImportUnencryptedKey extends Type<'importUnencryptedKey'>{
      local_password: Types.SecureBytes;
      exported_unencrypted_key: Types.ExportedUnencryptedKey;
    }
    export interface Init extends Type<'init'>{
      options: Types.Options;
    }
    export interface Kdf extends Type<'kdf'>{
      password: Types.SecureBytes;
      salt: Types.SecureBytes;
      iterations: Types.Int32;
    }
    export interface OnLiteServerQueryError extends Type<'onLiteServerQueryError'>{
      id: Types.Int64;
      error: Types.Error;
    }
    export interface OnLiteServerQueryResult extends Type<'onLiteServerQueryResult'>{
      id: Types.Int64;
      bytes: Types.Bytes;
    }
    export interface PackAccountAddress extends Type<'packAccountAddress'>{
      account_address: Types.UnpackedAccountAddress;
    }
    export interface RunTests extends Type<'runTests'>{
      dir: Types.String;
    }
    export interface SetLogStream extends Type<'setLogStream'>{
      log_stream: Types.LogStream;
    }
    export interface SetLogTagVerbosityLevel extends Type<'setLogTagVerbosityLevel'>{
      tag: Types.String;
      new_verbosity_level: Types.Int32;
    }
    export interface SetLogVerbosityLevel extends Type<'setLogVerbosityLevel'>{
      new_verbosity_level: Types.Int32;
    }
    export interface Sync extends Type<'sync'>{
    }
    export interface UnpackAccountAddress extends Type<'unpackAccountAddress'>{
      account_address: Types.String;
    }
    export interface WithBlock extends Type<'withBlock'>{
      id: Types.Ton.BlockIdExt;
      function: Types.Function;
    }
    export namespace Raw {
      export interface AccountState extends Type<'raw.accountState'>{
        code: Types.Bytes;
        data: Types.Bytes;
        frozen_hash: Types.Bytes;
      }
      export interface InitialAccountState extends Type<'raw.initialAccountState'>{
        code: Types.Bytes;
        data: Types.Bytes;
      }
      export interface FullAccountState extends Type<'raw.fullAccountState'>{
        balance: Types.Int64;
        code: Types.Bytes;
        data: Types.Bytes;
        last_transaction_id: Types.Internal.TransactionId;
        block_id: Types.Ton.BlockIdExt;
        frozen_hash: Types.Bytes;
        sync_utime: Types.Int53;
      }
      export interface Message extends Type<'raw.message'>{
        source: Types.AccountAddress;
        destination: Types.AccountAddress;
        value: Types.Int64;
        fwd_fee: Types.Int64;
        ihr_fee: Types.Int64;
        created_lt: Types.Int64;
        body_hash: Types.Bytes;
        msg_data: Types.Msg.Data;
      }
      export interface Transaction extends Type<'raw.transaction'>{
        utime: Types.Int53;
        data: Types.Bytes;
        transaction_id: Types.Internal.TransactionId;
        fee: Types.Int64;
        storage_fee: Types.Int64;
        other_fee: Types.Int64;
        in_msg: Types.Raw.Message;
        out_msgs: Types.Vector<Types.Raw.Message>;
      }
      export interface Transactions extends Type<'raw.transactions'>{
        transactions: Types.Vector<Types.Raw.Transaction>;
        previous_transaction_id: Types.Internal.TransactionId;
      }
      export interface CreateAndSendMessage extends Type<'raw.createAndSendMessage'>{
        destination: Types.AccountAddress;
        initial_account_state: Types.Bytes;
        data: Types.Bytes;
      }
      export interface CreateQuery extends Type<'raw.createQuery'>{
        destination: Types.AccountAddress;
        init_code: Types.Bytes;
        init_data: Types.Bytes;
        body: Types.Bytes;
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
        body: Types.Bytes;
      }
    }
    
    export namespace Wallet {
      export namespace V3 {
        export interface AccountState extends Type<'wallet.v3.accountState'>{
          wallet_id: Types.Int64;
          seqno: Types.Int32;
        }
        export interface InitialAccountState extends Type<'wallet.v3.initialAccountState'>{
          public_key: Types.String;
          wallet_id: Types.Int64;
        }
      }
      
      export namespace Highload {
        export namespace V1 {
          export interface AccountState extends Type<'wallet.highload.v1.accountState'>{
            wallet_id: Types.Int64;
            seqno: Types.Int32;
          }
          export interface InitialAccountState extends Type<'wallet.highload.v1.initialAccountState'>{
            public_key: Types.String;
            wallet_id: Types.Int64;
          }
        }
        
        export namespace V2 {
          export interface AccountState extends Type<'wallet.highload.v2.accountState'>{
            wallet_id: Types.Int64;
          }
          export interface InitialAccountState extends Type<'wallet.highload.v2.initialAccountState'>{
            public_key: Types.String;
            wallet_id: Types.Int64;
          }
        }
      }
    }
    
    export namespace Dns {
      export interface AccountState extends Type<'dns.accountState'>{
        wallet_id: Types.Int64;
      }
      export interface InitialAccountState extends Type<'dns.initialAccountState'>{
        public_key: Types.String;
        wallet_id: Types.Int64;
      }
      export interface ActionDeleteAll extends Type<'dns.actionDeleteAll'>{
      }
      export interface ActionDelete extends Type<'dns.actionDelete'>{
        name: Types.String;
        category: Types.Int32;
      }
      export interface ActionSet extends Type<'dns.actionSet'>{
        entry: Types.Dns.Entry;
      }
      export interface Entry extends Type<'dns.entry'>{
        name: Types.String;
        category: Types.Int32;
        entry: Types.Dns.EntryData;
      }
      export interface EntryDataUnknown extends Type<'dns.entryDataUnknown'>{
        bytes: Types.Bytes;
      }
      export interface EntryDataText extends Type<'dns.entryDataText'>{
        text: Types.String;
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
        entries: Types.Vector<Types.Dns.Entry>;
      }
      export interface Resolve extends Type<'dns.resolve'>{
        account_address: Types.AccountAddress;
        name: Types.String;
        category: Types.Int32;
        ttl: Types.Int32;
      }
    }
    
    export namespace Rwallet {
      export interface AccountState extends Type<'rwallet.accountState'>{
        wallet_id: Types.Int64;
        seqno: Types.Int32;
        unlocked_balance: Types.Int64;
        config: Types.Rwallet.Config;
      }
      export interface InitialAccountState extends Type<'rwallet.initialAccountState'>{
        init_public_key: Types.String;
        public_key: Types.String;
        wallet_id: Types.Int64;
      }
      export interface ActionInit extends Type<'rwallet.actionInit'>{
        config: Types.Rwallet.Config;
      }
      export interface Config extends Type<'rwallet.config'>{
        start_at: Types.Int53;
        limits: Types.Vector<Types.Rwallet.Limit>;
      }
      export interface Limit extends Type<'rwallet.limit'>{
        seconds: Types.Int32;
        value: Types.Int64;
      }
    }
    
    export namespace Pchan {
      export interface AccountState extends Type<'pchan.accountState'>{
        config: Types.Pchan.Config;
        state: Types.Pchan.State;
        description: Types.String;
      }
      export interface InitialAccountState extends Type<'pchan.initialAccountState'>{
        config: Types.Pchan.Config;
      }
      export interface ActionInit extends Type<'pchan.actionInit'>{
        inc_A: Types.Int64;
        inc_B: Types.Int64;
        min_A: Types.Int64;
        min_B: Types.Int64;
      }
      export interface ActionClose extends Type<'pchan.actionClose'>{
        extra_A: Types.Int64;
        extra_B: Types.Int64;
        promise: Types.Pchan.Promise;
      }
      export interface ActionTimeout extends Type<'pchan.actionTimeout'>{
      }
      export interface Config extends Type<'pchan.config'>{
        alice_public_key: Types.String;
        alice_address: Types.AccountAddress;
        bob_public_key: Types.String;
        bob_address: Types.AccountAddress;
        init_timeout: Types.Int32;
        close_timeout: Types.Int32;
        channel_id: Types.Int64;
      }
      export interface Promise extends Type<'pchan.promise'>{
        signature: Types.Bytes;
        promise_A: Types.Int64;
        promise_B: Types.Int64;
        channel_id: Types.Int64;
      }
      export interface StateInit extends Type<'pchan.stateInit'>{
        signed_A: Types.Bool;
        signed_B: Types.Bool;
        min_A: Types.Int64;
        min_B: Types.Int64;
        expire_at: Types.Int53;
        A: Types.Int64;
        B: Types.Int64;
      }
      export interface StateClose extends Type<'pchan.stateClose'>{
        signed_A: Types.Bool;
        signed_B: Types.Bool;
        min_A: Types.Int64;
        min_B: Types.Int64;
        expire_at: Types.Int53;
        A: Types.Int64;
        B: Types.Int64;
      }
      export interface StatePayout extends Type<'pchan.statePayout'>{
        A: Types.Int64;
        B: Types.Int64;
      }
      export interface PackPromise extends Type<'pchan.packPromise'>{
        promise: Types.Pchan.Promise;
      }
      export interface SignPromise extends Type<'pchan.signPromise'>{
        input_key: Types.InputKey;
        promise: Types.Pchan.Promise;
      }
      export interface UnpackPromise extends Type<'pchan.unpackPromise'>{
        data: Types.SecureBytes;
      }
      export interface ValidatePromise extends Type<'pchan.validatePromise'>{
        public_key: Types.Bytes;
        promise: Types.Pchan.Promise;
      }
    }
    
    export namespace Uninited {
      export interface AccountState extends Type<'uninited.accountState'>{
        frozen_hash: Types.Bytes;
      }
    }
    
    export namespace Ton {
      export interface BlockId extends Type<'ton.blockId'>{
        workchain: Types.Int32;
        shard: Types.Int64;
        seqno: Types.Int32;
      }
      export interface BlockIdExt extends Type<'ton.blockIdExt'>{
        workchain: Types.Int32;
        shard: Types.Int64;
        seqno: Types.Int32;
        root_hash: Types.Bytes;
        file_hash: Types.Bytes;
      }
    }
    
    export namespace Internal {
      export interface TransactionId extends Type<'internal.transactionId'>{
        lt: Types.Int64;
        hash: Types.Bytes;
      }
    }
    
    export namespace LiteServer {
      export interface Info extends Type<'liteServer.info'>{
        now: Types.Int53;
        version: Types.Int32;
        capabilities: Types.Int64;
      }
      export interface GetInfo extends Type<'liteServer.getInfo'>{
      }
    }
    
    export namespace Msg {
      export interface DataRaw extends Type<'msg.dataRaw'>{
        body: Types.Bytes;
        init_state: Types.Bytes;
      }
      export interface DataText extends Type<'msg.dataText'>{
        text: Types.Bytes;
      }
      export interface DataDecryptedText extends Type<'msg.dataDecryptedText'>{
        text: Types.Bytes;
      }
      export interface DataEncryptedText extends Type<'msg.dataEncryptedText'>{
        text: Types.Bytes;
      }
      export interface DataDecrypted extends Type<'msg.dataDecrypted'>{
        proof: Types.Bytes;
        data: Types.Msg.Data;
      }
      export interface DataDecryptedArray extends Type<'msg.dataDecryptedArray'>{
        elements: Types.Vector<Types.Msg.DataDecrypted>;
      }
      export interface DataEncrypted extends Type<'msg.dataEncrypted'>{
        source: Types.AccountAddress;
        data: Types.Msg.Data;
      }
      export interface DataEncryptedArray extends Type<'msg.dataEncryptedArray'>{
        elements: Types.Vector<Types.Msg.DataEncrypted>;
      }
      export interface Message extends Type<'msg.message'>{
        destination: Types.AccountAddress;
        public_key: Types.String;
        amount: Types.Int64;
        data: Types.Msg.Data;
      }
      export interface Decrypt extends Type<'msg.decrypt'>{
        input_key: Types.InputKey;
        data: Types.Msg.DataEncryptedArray;
      }
      export interface DecryptWithProof extends Type<'msg.decryptWithProof'>{
        proof: Types.Bytes;
        data: Types.Msg.DataEncrypted;
      }
    }
    
    export namespace Options {
      export interface ConfigInfo extends Type<'options.configInfo'>{
        default_wallet_id: Types.Int64;
        default_rwallet_init_public_key: Types.String;
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
        destination_fees: Types.Vector<Types.Fees>;
      }
      export interface Info extends Type<'query.info'>{
        id: Types.Int53;
        valid_until: Types.Int53;
        body_hash: Types.Bytes;
        body: Types.Bytes;
        init_state: Types.Bytes;
      }
      export interface EstimateFees extends Type<'query.estimateFees'>{
        id: Types.Int53;
        ignore_chksig: Types.Bool;
      }
      export interface Forget extends Type<'query.forget'>{
        id: Types.Int53;
      }
      export interface GetInfo extends Type<'query.getInfo'>{
        id: Types.Int53;
      }
      export interface Send extends Type<'query.send'>{
        id: Types.Int53;
      }
    }
    
    export namespace Smc {
      export interface Info extends Type<'smc.info'>{
        id: Types.Int53;
      }
      export interface MethodIdNumber extends Type<'smc.methodIdNumber'>{
        number: Types.Int32;
      }
      export interface MethodIdName extends Type<'smc.methodIdName'>{
        name: Types.String;
      }
      export interface RunResult extends Type<'smc.runResult'>{
        gas_used: Types.Int53;
        stack: Types.Vector<Types.Tvm.StackEntry>;
        exit_code: Types.Int32;
      }
      export interface GetCode extends Type<'smc.getCode'>{
        id: Types.Int53;
      }
      export interface GetData extends Type<'smc.getData'>{
        id: Types.Int53;
      }
      export interface GetState extends Type<'smc.getState'>{
        id: Types.Int53;
      }
      export interface Load extends Type<'smc.load'>{
        account_address: Types.AccountAddress;
      }
      export interface RunGetMethod extends Type<'smc.runGetMethod'>{
        id: Types.Int53;
        method: Types.Smc.MethodId;
        stack: Types.Vector<Types.Tvm.StackEntry>;
      }
    }
    
    export namespace Tvm {
      export interface Cell extends Type<'tvm.cell'>{
        bytes: Types.Bytes;
      }
      export interface List extends Type<'tvm.list'>{
        elements: Types.Vector<Types.Tvm.StackEntry>;
      }
      export interface NumberDecimal extends Type<'tvm.numberDecimal'>{
        number: Types.String;
      }
      export interface Slice extends Type<'tvm.slice'>{
        bytes: Types.Bytes;
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
        elements: Types.Vector<Types.Tvm.StackEntry>;
      }
    }
  }
}
