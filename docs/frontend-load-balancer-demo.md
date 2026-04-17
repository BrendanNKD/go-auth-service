# Frontend Load Balancer Demo Page

This doc describes how a frontend can create a demo page that shows ECS autoscaling and load-balancer distribution for `auth-service`.

The goal is simple: keep calling the auth service through the public load balancer, label the first task as `A`, then show `B`, `C`, and onward when requests start landing on newly scaled tasks.

## Backend Endpoint

Use this endpoint from the frontend:

```http
GET /api/v1/debug/instance
```

The endpoint does not require auth. It returns a small identity payload for the backend task that handled the request.

Example response:

```json
{
  "service": "auth-service",
  "instance_id": "1234567890abcdef1234567890abcdef",
  "display_id": "8f14e45fceea",
  "hostname": "ip-10-0-1-25.ap-southeast-1.compute.internal",
  "task_id": "1234567890abcdef1234567890abcdef",
  "task_family": "auth-service",
  "task_revision": "42",
  "availability_zone": "ap-southeast-1a",
  "launch_type": "FARGATE",
  "source": "ecs-task-metadata",
  "time_utc": "2026-04-17T12:00:00Z"
}
```

Important fields for the UI:

| Field | Use |
| --- | --- |
| `instance_id` | Stable unique key for the backend task. Use this for A/B/C labeling. |
| `display_id` | Short safe value to show in the UI. |
| `task_id` | ECS task id. Show only if useful for debugging. |
| `hostname` | Fallback identity outside ECS. |
| `source` | Shows whether the value came from ECS metadata, env override, hostname, or process fallback. |
| `time_utc` | Last backend response time. |

Always call this endpoint through the load balancer URL, not a direct task URL. Direct task calls bypass the behavior this page is trying to demonstrate.

## Demo Route Already Available

The auth service also serves a built-in reference page:

```http
GET /lb-demo
```

Frontend teams can either use that page directly or recreate the same behavior inside another app. If building a separate frontend, use `/api/v1/debug/instance` as the source of truth.

## User Flow

1. Open the demo page while the ECS service has one healthy task.
2. The first successful response is labeled `A`.
3. Start repeated calls from the page.
4. Scale the ECS service to two or more tasks.
5. When the load balancer sends a request to a new task, the frontend assigns the next label, such as `B`.
6. Keep a recent-call list so the viewer can see traffic moving between `A`, `B`, and any later tasks.

The visible transition should be obvious:

```text
Current target: A
Seen tasks: A

After scale-out and traffic distribution:

Current target: B
Seen tasks: A, B
Recent calls: A, A, B, A, B
```

## UI Requirements

The page should include:

| UI element | Behavior |
| --- | --- |
| Current target label | Large `A`, `B`, `C`, etc. Changes when a different task handles the latest request. |
| Task count | Number of unique `instance_id` values seen by this browser. |
| Call count | Number of API calls made by the page. |
| Recent calls | List of the last 10-20 calls with label and `display_id`. |
| Call once button | Sends one request to `/api/v1/debug/instance`. |
| Auto call toggle | Sends a request every 500-1000 ms. |
| Burst button | Sends around 20 concurrent requests to make distribution easier to see. |
| Reset button | Clears stored labels and history. |
| Error message | Shows HTTP or network failures clearly. |

Keep labels stable during refreshes by saving the label map in `localStorage`. Without this, the same task could become `A` again after every page reload, which makes the transition less clear.

## Labeling Logic

Use `instance_id` as the identity key. If it is missing, fall back to `hostname`, then `"unknown"`.

Suggested logic:

```js
const labelsKey = "authServiceLoadBalancerDemo.labels";
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");

function loadLabels() {
  try {
    return JSON.parse(localStorage.getItem(labelsKey)) || {};
  } catch {
    return {};
  }
}

function saveLabels(labels) {
  localStorage.setItem(labelsKey, JSON.stringify(labels));
}

function labelForInstance(instanceId, labels) {
  if (!labels[instanceId]) {
    const index = Object.keys(labels).length;
    labels[instanceId] = alphabet[index] || `#${index + 1}`;
    saveLabels(labels);
  }
  return labels[instanceId];
}
```

## Fetch Example

Use `cache: "no-store"` and add a timestamp query parameter so browser or proxy caching does not hide backend changes.

```js
async function fetchCurrentInstance(callNumber) {
  const response = await fetch(
    `/api/v1/debug/instance?t=${Date.now()}-${callNumber}`,
    {
      cache: "no-store",
      headers: {
        Accept: "application/json"
      }
    }
  );

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}
```

## Rendering Example

```js
const state = {
  calls: 0,
  labels: loadLabels(),
  history: []
};

async function callInstance() {
  state.calls += 1;

  const data = await fetchCurrentInstance(state.calls);
  const identity = data.instance_id || data.hostname || "unknown";
  const label = labelForInstance(identity, state.labels);

  state.history.unshift({
    label,
    displayId: data.display_id || identity,
    source: data.source,
    timeUTC: data.time_utc
  });
  state.history = state.history.slice(0, 20);

  render({
    currentLabel: label,
    calls: state.calls,
    taskCount: Object.keys(state.labels).length,
    displayId: data.display_id || identity,
    taskId: data.task_id,
    hostname: data.hostname,
    source: data.source,
    history: state.history
  });
}
```

## Polling And Burst Behavior

Auto polling is useful for showing the moment a new task starts receiving traffic:

```js
let timer = null;

function startAutoCalls() {
  if (timer) return;
  timer = setInterval(callInstance, 700);
}

function stopAutoCalls() {
  clearInterval(timer);
  timer = null;
}
```

Burst calls are useful after scale-out because the load balancer may not switch target on every sequential browser request:

```js
async function burstCalls() {
  await Promise.allSettled(
    Array.from({ length: 20 }, () => callInstance())
  );
}
```

## Demo Script

Use this flow when presenting the transition:

1. Set the ECS desired count to `1`.
2. Open the frontend demo page through the ALB URL.
3. Click `Reset`.
4. Click `Call once`. The current target should become `A`.
5. Click `Start auto calls`.
6. Scale the ECS service desired count to `2` or more.
7. Wait until the target group shows the new task as healthy.
8. Watch for the page to show `B`.
9. Click `Burst 20` if it still shows only `A`.

## Troubleshooting

If the page never shows `B`, check these first:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Only `A` appears after scaling | New ECS task is not healthy in the target group yet. | Wait for target health or inspect ECS service events. |
| Only `A` appears with multiple healthy targets | ALB target-group stickiness may be enabled. | Disable stickiness for the demo or wait for the sticky session to expire. |
| Response source is `hostname` | ECS metadata env var is not available. | Confirm the service runs on ECS and metadata endpoint access is present. |
| Browser gets CORS errors | Frontend is hosted on a different origin. | Add that origin to the auth-service CORS configuration. |
| The label changes after page refresh | Labels are not persisted. | Store the `instance_id -> label` map in `localStorage`. |
| Calls look cached | Browser or proxy cache is serving old responses. | Use `cache: "no-store"` and add a timestamp query parameter. |

## Security Notes

This endpoint is for demonstration and operational visibility. It should not return secrets, environment variables, full task ARNs, tokens, cookies, database settings, or Valkey settings.

For production demos, prefer showing `display_id`, label, source, availability zone, and launch type. Avoid exposing account ids, full infrastructure identifiers, or anything that helps identify private network details.

If the page is only needed for internal demos, place it behind an internal route, internal ALB, VPN, or another access control layer.
