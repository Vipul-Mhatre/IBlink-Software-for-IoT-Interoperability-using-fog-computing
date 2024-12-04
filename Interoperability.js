import { Web5 } from '@web5/api';
import { VerifiableCredential } from '@web5/credentials';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

// ------------------Step 1: Create Bob's DID and DWN------------------

// Create DID for Bob and connect to his DWN
const { web5, did: bobDid } = await Web5.connect();

// Create Bearer DID for Bob
const { did: bobBearerDid } = await web5.agent.identity.get({ didUri: bobDid });

// ------------------Step 2: Configure VC Protocol on Bob's DWN------------------

await web5.dwn.protocols.configure({
    message: {
        protocol: 'https://vc-to-dwn.tbddev.org/vc-protocol',
        definition: {
            published: true,
            types: {
                credential: {
                    schema: 'https://vc-to-dwn.tbddev.org/vc-protocol/schema/credential',
                    dataFormats: ['application/vc+jwt']
                },
                issuer: {
                    schema: 'https://vc-to-dwn.tbddev.org/vc-protocol/schema/issuer',
                    dataFormats: ['text/plain']
                },
                judge: {
                    schema: 'https://vc-to-dwn.tbddev.org/vc-protocol/schema/judge',
                    dataFormats: ['text/plain']
                }
            },
            structure: {
                issuer: {
                    $role: true
                },
                judge: {
                    $role: true
                },
                credential: {
                    $actions: [
                        {
                            role: 'issuer',
                            can: ['create']
                        },
                        {
                            role: 'judge',
                            can: ['query', 'read', 'subscribe'] // Include all required read actions
                        }
                    ]
                }
            }
        }
    }
});

// ------------------Step 3: Create and Sign VC for Alice------------------

const aliceDid = 'did:dht:rr1w5z9hdjtt76e6zmqmyyxc5cfnwjype6prz45m6z1qsbm8yjao';

// Create a Verifiable Credential for Alice
const vc = await VerifiableCredential.create({
    type: 'creatingVerifiableCredentialForAlice',
    issuer: bobDid,
    subject: aliceDid,
    data: {
        name: 'Alice Smith',
        completionDate: new Date().toISOString(),
    }
});

// Sign the Verifiable Credential with Bob's Bearer DID
const signedVc = await vc.sign({ did: bobBearerDid });

// ------------------Step 4: Request Authorization to Write to Alice's DWN------------------

// Request permission to write to Alice’s DWN
const authorizationResponse = await fetch(`https://vc-to-dwn.tbddev.org/authorize?issuerDid=${bobDid}`);
const authorizationToken = await authorizationResponse.text();

// ------------------Step 5: Store the Signed VC in Alice's DWN------------------

const { record } = await web5.dwn.records.create({
    data: signedVc,
    message: {
        schema: 'https://vc-to-dwn.tbddev.org/vc-protocol/schema/credential',
        dataFormat: 'application/vc+jwt',
        published: true,
        authorization: authorizationToken // Use authorization token obtained above
    }
});

//console.log('Credential successfully stored in Alice’s DWN:', record);

console.log('DWN Record ID:', record._recordId);
