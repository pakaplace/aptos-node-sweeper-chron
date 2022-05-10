import { AptosClient, AptosAccount, FaucetClient, Types } from './aptos';
import {
  Account,
  RestClient,
  convertUnit8ArrayToHex,
  convertHexStringToUint8Array,
} from './aptos-utils';
const NODE_URL =
  process.env.APTOS_NODE_URL || 'https://fullnode.devnet.aptoslabs.com';
const FAUCET_URL =
  process.env.APTOS_FAUCET_URL || 'https://faucet.devnet.aptoslabs.com';
const aptosClientV1 = new RestClient(NODE_URL);
const aptosClientV2 = new AptosClient(NODE_URL);
//    const freshSKHex = convertUnit8ArrayToHex(freshAccount.signingKey.secretKey).slice(0, 64)
const daveAK =
  'efa78f06b7c0d7f71d5c9ba13f6c695582939e4a3b6a638204395c976dade733';
const davePK =
  '58FB457407E86F21A71919FAF1B89C9446E11A89D1CBE95630188D7B54F74849';

export default async function sweepToDestinationAddress(
  destinationAddress: string,
  amount?: number
) {
  if (destinationAddress && destinationAddress.length !== 64)
    return console.error('Address must be a 64 character hex string');
  const restoredAccount = AptosAccount.fromAptosAccountObject({
    privateKeyHex: davePK,
    address: daveAK,
  });
  const faucetClient = new FaucetClient(NODE_URL, FAUCET_URL, null);
  await faucetClient.fundAccount(restoredAccount.authKey(), 2);
  await faucetClient.fundAccount(destinationAddress, 2);
  try {
    const startNodeBalance: number = await aptosClientV1.accountBalance(
      restoredAccount.authKey().toString()
    );
    const startDestinationBalance: number = await aptosClientV1.accountBalance(
      destinationAddress
    );
    console.log('\n=== start Balances ===');
    console.log(`Your Node: ${startNodeBalance}`);
    console.log(`Desination: ${startDestinationBalance}`);

    if (startNodeBalance > 1) {
      // const amountToSend:number = amount ? amount : nodeBalance;
      // const restoredSenderAccount = new Account(undefined, restoredAccount.signingKey.secretKey)
      const payload: {
        function: string;
        arguments: string[];
        type: string;
        type_arguments: any[];
      } = {
        type: 'script_function_payload',
        function: '0x1::TestCoin::transfer',
        type_arguments: [],
        arguments: [`0x${destinationAddress}`, amount.toString()],
      };
      const generatedTransferTx = await aptosClientV2.generateTransaction(
        restoredAccount.authKey(),
        payload
      );
      const signedTransferTx = await aptosClientV2.signTransaction(
        restoredAccount,
        generatedTransferTx
      );
      const submittedTransferTx = await aptosClientV2.submitTransaction(
        restoredAccount,
        signedTransferTx
      );
      // const txHash = await aptosClientV1.transfer(restoredSenderAccount, destinationAddress, amountToSend);
      await aptosClientV1.waitForTransaction(submittedTransferTx.hash);

      const endNodeBalance = await aptosClientV1.accountBalance(
        restoredAccount.authKey().toString()
      );
      const endDestinationBalance = await aptosClientV1.accountBalance(
        destinationAddress
      );
      console.log('\n=== Final Balances ===');
      console.log(`Your Node: ${endNodeBalance}`);
      console.log(`Destination: ${endDestinationBalance}`);
      console.log(
        `Fee Paid: ${
          startNodeBalance +
          startDestinationBalance -
          endNodeBalance -
          endDestinationBalance
        }`
      );
    }
  } catch (err) {
    console.error(
      'Account does not exist on Aptos - No Token Balance found...\n',
      err
    );
  }
}
sweepToDestinationAddress(
  '855336a244dbac858102bb4d3fadae6a9912b8ff0907cbc2ba7ac3427a83193c',
  1
);
