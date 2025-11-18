- `ukify.xml`
  - [ ] `<programlisting>` with text and `<xi:include>`
- `bootctl.xml`
  - [ ] program listing at the end is not rendered as a code block
- `standard-conf.xml`
  - [ ] the `xpointer="usr-local-footnote"` import adds _both_ the footnote link as well as the footnote. This isn’t possible in rst, afaik. Used in:
    ```
    man/standard-conf.xml
    man/systemd.environment-generator.xml
    man/systemd.generator.xml
    man/systemd.link.xml
    man/systemd.network.xml
    man/systemd.unit.xml
    ```
