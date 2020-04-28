#buildWithParameters issues
Spent a couple of days researching how to stop Jenkins build. First of all, job's nextBuildNumber field doesn't necessarily equals to build number: if there's jobs exist in queue than enqueued build number may be changed during queue operations like stopping. So the only safe way to identify build job that was started is queueId. 

But it is not easy to get that queueId: it is not returned after "build" API endpoint call. We must call buildWithParameters endpoint and read Location header value in the response. QueueId will be represented as part of redirection URL like https://ci.domain.org/queue/item/406/

One more problem: for "build" API it is quite easy to pass any set of build parameters: that API accepts HTML form with parameters and we also may pass JSON-serialized parameters as "json" form field.

But (yes, one more "but") "buildWithParameters" API differs from "build": the only way to pass parameters is to use query parameters (see https://swagger.io/docs/specification/describing-parameters/#query-parameters). And as we can't describe arbitrary set of query parameters in OpenAPi specification, the only way is to hardcode required parameters.
   