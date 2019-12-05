## cifv3_responder

A Cortex responder for CIFv3

Responder will submit case and alert artifacts to a CIFv3 server.

Configuration Parameters:

- CIF API URL
- CIF API Token
- Verify API SSL (True/False) (defaults to 'True')
- Default confidence level for indicators (defaults to '5')
- Default group to submit to (defaults to 'everyone')
- TLP Map to map TheHive TLP (white, green, etc.) to a custom TLP, in the form of a JSON object. For example, to map 'amber' to 'privileged':

`{"2": "privileged"}`

See [TheHive doc][https://github.com/TheHive-Project/TheHiveDocs/blob/master/api/case.md] for TLP numerical values.

Artifact Tags:

   - Indicator tags (botnet, malware, etc.) are derived from artifact tags. 
   - Confidence can be set on a per-artifact basis by adding the `confidence:[0-10]` tag to the artifact. If not specified, the default confidence level is used.
   - All other directive tags (e.g. `key:value`) are ignored
   
For example, a artifact with the tags `phishing, malware, confidence:7` will create an indicator with the tag of `phishing, malware` at a confidence of `7`. 


[https://github.com/TheHive-Project/TheHiveDocs/blob/master/api/case.md]: https://github.com/TheHive-Project/TheHiveDocs/blob/master/api/case.md