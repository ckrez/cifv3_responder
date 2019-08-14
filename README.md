## cifv3_responder

A Cortex responder for CIFv3

Responder will submit case and alert artifacts to a CIFv3 server.

Configuration Parameters:

- CIF API URL
- CIF API Token
- Verify API SSL (True/False) (defaults to 'True')
- Default confidence level for indicators (defaults to '5')
- Default group to submit to (defaults to 'everyone')

Artifact Tags:

   - Indicator tags (botnet, malware, etc.) are derived from artifact tags. 
   - Confidence can be set on a per-artifact basis by adding the `confidence:[0-10]` tag to the artifact. If not specified, the default confidence level is used.

For example, a artifact with the tags `phishing, malware, confidence:7` will create an indicator with the tag of `phishing, malware` at a confidence of `7`. 
