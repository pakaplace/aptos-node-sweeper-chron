import { successResponse, runWarm } from './utils';
import { Response } from './utils/lambda-response';
import sweepToDestinationAddress from './sweeper';

const handler = async (event: AWSLambda.APIGatewayEvent): Promise<Response> => {
  // successResponse handles wrapping the response in an API Gateway friendly
  // format (see other responses, including CORS, in `./utils/lambda-response.ts)
  console.log('PING');
  await sweepToDestinationAddress(
    '855336a244dbac858102bb4d3fadae6a9912b8ff0907cbc2ba7ac3427a83193c',
    1
  );
  const response = successResponse({
    message: 'Go Serverless! Your function executed successfully!',
    input: event,
  });

  return response;
};

// runWarm function handles pings from the scheduler so you don't
// have to put that boilerplate in your function.
export default runWarm(handler);
