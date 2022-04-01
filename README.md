
# TON Blockchain TypeScript Type Declarations

This repository contains TypeScript typing declarations for
various TON Blockchain type schemas and are automatically
generated from TL-B schemas.


## Content

| Schema Name | TL-B Schema                                                                                  | Type Declarations                         | Description |
| ----------- |----------------------------------------------------------------------------------------------|-------------------------------------------| ----------- |
| tonlib      | [(open)](https://github.com/ton-blockchain/ton/blob/master/tl/generate/scheme/tonlib_api.tl) | [(open)](./types/tonlib.d.ts)  | Tonlib API  |


## Install

Install the library:

```shell
npm install --save-dev @ton.js/types
```


## Use

Import the required types and use them:

```typescript
import { TonLib } from '@ton.js/types';


function getTotalFees(fees: TonLib.Types.Fees): TonLib.Types.Int53 {

  return (
    fees.in_fwd_fee +
    fees.storage_fee +
    fees.gas_fee +
    fees.fwd_fee
  );

}
```


## License (MIT)

**Copyright © 2022 TON FOUNDATION**

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
