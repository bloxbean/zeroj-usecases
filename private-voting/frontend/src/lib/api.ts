const BASE_URL = '/api';

async function post(path: string, body: Record<string, any> = {}): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function get(path: string): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`);
  return res.json();
}

export const api = {
  // Election
  electionStatus: () => get('/election/status'),
  createElection: (name: string) => post('/election/create', { name }),
  registerVoter: (label: string, secretKey: string) =>
    post('/election/register', { label, secretKey }),
  finalizeElection: () => post('/election/finalize'),

  // Voting
  castVote: (voterLabel: string, vote: number) =>
    post('/vote', { voterLabel, vote }),

  // Results
  results: () => get('/results'),

  // Status
  status: () => get('/status'),
};
