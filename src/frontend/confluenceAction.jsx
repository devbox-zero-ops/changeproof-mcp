import React, { useEffect, useState } from 'react';
import ForgeReconciler, {
  Heading,
  Inline,
  Lozenge,
  SectionMessage,
  Stack,
  Text,
} from '@forge/react';
import { invoke } from '@forge/bridge';

function ConfluenceActionApp() {
  const [state, setState] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    void invoke('getConfluenceSopImpact', {})
      .then((res) => {
        if (res && res.ok) setState(res);
        else setError(res?.error || 'Could not inspect SOP impact.');
      })
      .catch((err) => setError(String(err)));
  }, []);

  if (error) {
    return (
      <SectionMessage appearance="error">
        <Text>{error}</Text>
      </SectionMessage>
    );
  }
  if (!state) {
    return <Text>Scanning linked Jira change requests and CAPAs for this SOP…</Text>;
  }

  return (
    <Stack space="space.150">
      <Heading as="h3">ChangeProof SOP Impact Monitor</Heading>
      <Inline space="space.100">
        <Lozenge appearance="inprogress">Version v{state.page.version}</Lozenge>
        <Lozenge appearance={state.activeChangeCount > 0 ? 'moved' : 'success'}>
          {state.activeChangeCount} Active Change Requests
        </Lozenge>
      </Inline>
      <Text>
        Controlled Doc Codes: {state.page.docCodes.length > 0 ? state.page.docCodes.join(', ') : 'None detected'}
      </Text>
      {state.linkedChanges.length === 0 ? (
        <SectionMessage appearance="confirmation">
          <Text>No open regulated change requests reference this procedure.</Text>
        </SectionMessage>
      ) : (
        <Stack space="space.075">
          {state.linkedChanges.map((item) => (
            <Inline key={item.key} space="space.100">
              <Lozenge appearance="default">{item.key}</Lozenge>
              <Text>
                {item.summary} ({item.status} · {item.priority})
              </Text>
            </Inline>
          ))}
        </Stack>
      )}
    </Stack>
  );
}

ForgeReconciler.render(
  <React.StrictMode>
    <ConfluenceActionApp />
  </React.StrictMode>,
);
