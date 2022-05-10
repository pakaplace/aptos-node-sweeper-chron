import handler from './handler';
import context from './test/utils/handler-helper';
import event from '../fixtures/event.json';

const callback = jest.fn();

describe('handler', () => {
  it.skip('executes as expected', async () => {
    const response = await handler(event, context, callback);
    expect(response).toMatchSnapshot();
  });
});
