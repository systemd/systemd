<?xml version='1.0'?> <!--*-nxml-*-->

<!--
  This file is part of systemd.

  Copyright 2015 Johan Ouwerkerk

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
-->

<!--
  - This stylesheet implements support for cross references within a set of man page files (docbook XML) in HTML form.
  -
  - Consumers need to determine which citerefentry constitutes a cross reference to another man page from the same project,
  - and then call determineCrossID template like this:

  <xsl:call-template name="determineCrossID">
    <xsl:with-param name="element" select="/select/the/citerefentry"/>
  </xsl:call-template>

  - When the current node is a citerefentry element, the default value of element means the call can be simplified to:

  <xsl:call-template name="determineCrossID"/>

  - The result of determineCrossID is a string which corresponds to the id of some subsection of the page being referenced,
  - or in other words: the stuff you want to put in the fragment part of a URL in a href attribute (the bit after #).
 -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:str="http://exslt.org/strings"
                xmlns:fn="http://exslt.org/functions"
                xmlns:refs="man.systemd.refs"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="fn str exsl" exclude-result-prefixes="fn str refs exsl">
<xsl:import href="permalink-id-scheme-html.xsl"/>
<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>


<!--
  - Helper template to generate cross reference hyperlink
 -->
<xsl:template name="reflink">
  <xsl:param name="href"/>
  <a href="{$href}"><xsl:call-template name="inline.charseq"/></a>
</xsl:template>


<xsl:param name="cross.refs.debug" select="'0'"/>

<!--
  - Helper template to determine the ID value of the href attribute for systemd cross reference links.
  - Right now it's just a wrapper, but in the future might need some more complex introspection here.
 -->
<xsl:template name="determineCrossID">

  <xsl:choose>
    <xsl:when test="normalize-space(string(manvolnum)) = '3'">
      <xsl:call-template name="reflink">
        <xsl:with-param name="href" select="concat(refentrytitle,'.html')"/>
      </xsl:call-template>
      <xsl:if test="$cross.refs.debug!='' and number($cross.refs.debug)!= 0">
        <xsl:value-of select="concat('c-api-exception ::&#x09;', refentrytitle)"/>
      </xsl:if>
    </xsl:when>
    <xsl:otherwise>

      <xsl:variable name="document" select="document(refs:rewrite-document-name(refentrytitle), refentrytitle)"/>

      <xsl:variable name="crossID">
        <xsl:apply-templates select="." mode="cross-refs">
          <xsl:with-param name="cross-refs-debug" select="''"/>
          <xsl:with-param name="document" select="$document"/>
        </xsl:apply-templates>
      </xsl:variable>


      <xsl:call-template name="reflink">
        <xsl:with-param name="href">
          <xsl:value-of select="concat(refentrytitle,'.html')"/>
          <xsl:if test="string($crossID)!=''">
            <xsl:value-of select="concat('#',$crossID)"/>
          </xsl:if>
        </xsl:with-param>
      </xsl:call-template>

      <xsl:if test="$cross.refs.debug!='' and number($cross.refs.debug)!= 0">
        <blockquote><pre>Debug info:<br/>
          <xsl:apply-templates select="." mode="cross-refs">
            <xsl:with-param name="cross-refs-debug" select="'debug'"/>
            <xsl:with-param name="document" select="$document"/>
          </xsl:apply-templates>
        </pre></blockquote>
      </xsl:if>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--
  - Helper function to return an upper case copy of a simple string ($str) containing just ASCII characters.
  - Non-ASCII characters are not translated.
  - Usage: use in XPATH expressions like this:
  -
    <xsl:variable name="uc" select="refs:toUpper($mixedCaseStr)"/>
  -
  - This function depends (obviously) on the EXSLT functions namespace.
  - See top of the stylesheet for the xmlns:fn declaration.
 -->
<fn:function name="refs:toUpper">
  <xsl:param name="str"/>
  <fn:result select="translate(string($str),'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
</fn:function>

<!--
  - Sometimes, man page name doesn't actually correspond with an XML source file because it refers to something
  - that is set as an alias refname.
  - Which is unfortunate because then document() will fail, which according to the XSLT spec permits xsltproc to
  - terminate the XSLT transformation with a fatal error (not that it will).
  -
  - Fortunately the number of offending man page names is low, if one ignore C API documentation (manvolnum = 3).
  - This means it's feasible to simply hard code the offenders and rewrite those to the proper XML source here.
  -
    <xsl:variable name="manPage" select="/select/some/citerefentry/reftitle"/>
    <xsl:variable name="xmlFile" select="refs:rewrite-document-name($manPage)"/>
  -
  - This function depends (obviously) on the EXSLT functions namespace.
  - See top of the stylesheet for the xmlns:fn declaration.
 -->
<fn:function name="refs:rewrite-document-name">
  <xsl:param name="man"/>
  <!--
    - By wrapping $man in spaces using concat() substring matches are rejected by contains().
    - Otherwise values like 'udev' would match to systemd-udevd even when these refer to their own XML (udev.xml).
   -->
  <xsl:variable name="serviceList" select="' systemd-udevd systemd-machined systemd-logind systemd-journald systemd-resolved '"/>
  <xsl:variable name="sleepList" select="' systemd-hibernate.service systemd-sleep systemd-hybrid-sleep.service '"/>
  <xsl:variable name="test" select="concat(' ', $man, ' ')"/>
  <fn:result>
    <xsl:choose>
      <xsl:when test="contains($sleepList, $test)">
        <xsl:value-of select="'systemd-suspend.service.xml'"/>
      </xsl:when>
      <xsl:when test="contains($serviceList, $test)">
        <xsl:value-of select="concat($man, '.service.xml')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="concat($man, '.xml')"/>
      </xsl:otherwise>
    </xsl:choose>
  </fn:result>
</fn:function>

<!--
  - Some systemd command line arguments happen to match other systemd directives/terms,
  - yet use a slightly different syntax.
  - This helper function rewrites the cli syntax to directive/term version.
  - The cli syntax is name.space.words_that_form_a_directive_name=
  - Where the corresponding directive name would be WordsThatFormADirectiveName=
  - Usage: use in XPATH expressions like this:
  -
    <xsl:variable name="directive" select="refs:rewrite-cli-query($cliArgument)"/>
  -
  - This function depends (obviously) on the EXSLT functions namespace.
  - See top of the stylesheet for the xmlns:fn declaration.
 -->
<fn:function name="refs:rewrite-cli-query">
  <xsl:param name="query"/>
  <xsl:variable name="afterLastDot" select="str:tokenize(string($query),'.')[last()]"/>
  <xsl:variable name="splitScores" select="str:tokenize(string($afterLastDot),'_')"/>
  <xsl:variable name="result">
    <xsl:for-each select="$splitScores">
      <xsl:variable name="chars" select="str:tokenize(string(.),'')"/>
      <xsl:value-of select="refs:toUpper(string($chars[1]))"/>
      <!--
        - copy-of is required because, only the first node in $chars[position() > 1] would otherwise be copied
        - (due to how value-of works with node sets).
       -->
      <xsl:copy-of select="$chars[position() &gt; 1]/text()"/>
    </xsl:for-each>
  </xsl:variable>
  <fn:result select="string($result)"/>
</fn:function>

<!--
  - Helper function to test if the text() value of an XML element matches a cross reference 'target' value.
  - (This function is not really intended to be a stand-alone function, use refs:node-set-matches() for
  - a much more convenient interface instead.)
  -
  - The function yields either 'found' or 'missing', instead of booleans because simple string comparisons are
  - consideraby easier to work with/grok if one doesn't live and breathe XSLT. Matching is a bit fuzzy to
  - compensate for various quirks of the source XMLs:
  -
  -  - If the node text ends with '=' then an alternative value without the trailing '=' is also considered to
  -    determine if the node matches. $altQuery is meant to be the corresponding alternative to $query so the
  -    logic applies consistently and all possible combinations of with/without trailing '=' are covered.
  -  - An alternative with normalized space for $query, $altQuery and the text values is also considered.
  -
  - Usage: use in an XPATH expression like this:
    <xsl:variable name="matches" select="$candidates[refs:node-matches(.,$query,$altQuery) = 'found']"/>
  -
  - This function depends (obviously) on the EXSLT functions namespace.
  - See top of the stylesheet for the xmlns:fn declaration.
 -->
<fn:function name="refs:node-matches">
  <xsl:param name="node"/>
  <xsl:param name="query"/>
  <xsl:param name="altQuery"/>
  <xsl:param name="text" select="string($node/text())"/>
  <xsl:variable name="result">
    <xsl:choose>
      <xsl:when test="$text = $query or $text = $altQuery">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="contains($text, '=') and (substring-before($text,'=') = $query or substring-before($text, '=') = $altQuery)">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="normalize-space($text) = normalize-space($query) or normalize-space($text) = normalize-space($altQuery)">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="contains($text, '=') and (normalize-space(substring-before($text,'=')) = normalize-space($query) or
                                                normalize-space(substring-before($text, '=')) = normalize-space($altQuery))">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="'missing'"/></xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <fn:result select="$result"/>
</fn:function>

<!--
  - Helper function to test if the structure of an XML element matches a cross reference 'target' value.
  -
  - The function yields either 'found' or 'missing', instead of booleans because simple string comparisons are
  - consideraby easier to work with/grok if one doesn't live and breathe XSLT. Matching is a bit fuzzy to
  - compensate for various quirks of the source XMLs using refs:node-matches().
  - The parameters $query and $altQuery are passed as-is to that function, which means that
  - $altQuery should have the last '=' character of $query removed.
  - Fortunately because of what $query/$altQuery refer to, this is simple:
  - if $query contains '=', $altQuery = substring-before($query,'=') or $altQuery = $query otherwise.
  -
  - Usage: use in an XPATH expression like this:
    <xsl:variable name="matches" select="$candidates[refs:node-matches(.,$query,$altQuery) = 'found']"/>
  -
  - This function depends (obviously) on the EXSLT functions namespace.
  - See top of the stylesheet for the xmlns:fn declaration.
 -->
<fn:function name="refs:node-set-matches">
  <xsl:param name="node"/>
  <xsl:param name="query"/>
  <xsl:param name="altQuery"/>

  <xsl:variable name="result">
    <xsl:choose>
      <xsl:when test="refs:node-matches($node, $query, $altQuery) = 'found'">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="count($node/varname[refs:node-matches(., $query, $altQuery) = 'found']) &gt; 0">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="count($node/option[refs:node-matches(., $query, $altQuery) = 'found']) &gt; 0">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="count($node/filename[refs:node-matches(., $query, $altQuery) = 'found']) &gt; 0">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:when test="count($node/command[refs:node-matches(., $query, $altQuery) = 'found']) &gt; 0">
        <xsl:value-of select="'found'"/>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="'missing'"/></xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <fn:result select="$result"/>
</fn:function>

<!--
  - Helper function to match a cross reference 'target' against nodes in the XML source for the given man page.
  -
  - This function yields a node set of XML elements that may be said to corrrespond to the given 'target' value.
  - Various nodes from referenced XML are attempted, to determine if these match as defined by refs:node-set-matches()
  - If the source XML for the given man page cannot be loaded or if no node can be matched to the given 'target',
  - an empty node set is returned.
  - Two parameters are used:
  - $target which will be converted to a string() and used as 'target' value.
  - $document which must be a node that when converted to string yields the name of the man page. It must be a node
  - in order to be able to open relative URIs as relative to the source which contains the references,
  - instead of some XSLT processor default (probably this stylesheet).
  -
 -->
<fn:function name="refs:matchRefID">
  <xsl:param name="target"/>
  <xsl:param name="refNodeSet"/>
  <!--
    - After loading the referenced man page XML into a node set, that XML document tree should be stripped down to the (hopefully) single
    - 'thing' (element) which matches the reference.
    - The slightly non-obvious thing is that in the case of 'term' nodes being referenced,
    - the node that *would* match may not be the first 'term' node in the varlistentry.
    - That would imply an invalid ID because of how permalinks to varlistentry/term lists are generated;
    - the solution is to fudge it by backing up to the parent node and then selecting the first term from there...
    -
    - ... That is the easy and fairly sane part. But there is more, further down the rabbit hole.
    - ... See: refs:node-set-matches(), refs:rewrite-document-name(), refs:rewrite-cli-query()
   -->
  <xsl:variable name="query" select="string($target)"/><!-- Use string to force string-ified comparison to aid the selector magic. -->

  <xsl:variable name="altQuery">
    <xsl:choose>
      <xsl:when test="contains($query, '=')">
        <xsl:value-of select="substring-before($query, '=')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$query"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:variable name="refMatchingSections" select="$refNodeSet//refsect2/title[refs:node-set-matches(., $query, $altQuery) = 'found']|
                                          $refNodeSet//refsect2/info/title[refs:node-set-matches(., $query, $altQuery) = 'found']|
                                          $refNodeSet//refsect1/title[refs:node-set-matches(., $query, $altQuery) = 'found']|
                                          $refNodeSet//refsect1/info/title[refs:node-set-matches(., $query, $altQuery) = 'found']"/>
  <xsl:variable name="refTerms" select="$refNodeSet//varlistentry/term"/>
  <xsl:variable name="refMatchingTerms" select="$refTerms[refs:node-set-matches(., $query, $altQuery) = 'found' or
                                                          refs:node-set-matches(., refs:rewrite-cli-query($query), refs:rewrite-cli-query($altQuery)) = 'found']"/>
  <xsl:variable name="refSelectMatchingTerms" select="$refMatchingTerms/parent::varlistentry/child::term[1]"/>
  <xsl:variable name="refMatches" select="$refMatchingSections|$refSelectMatchingTerms"/>
  <fn:result select="$refMatches"/>
</fn:function>

<fn:function name="refs:findMatchesForID">
  <xsl:param name="target"/>
  <xsl:param name="document"/>
  <xsl:variable name="crossRefSet">
    <xsl:for-each select="$target">
       <xsl:copy-of select="refs:matchRefID(., $document)"/>
    </xsl:for-each>
  </xsl:variable>

  <fn:result select="$crossRefSet"/>
</fn:function>

<!--
  - Helper template to retraces/invokes the generateID machinery for/on a cross referenced node.
  - It outputs the corresponding value for the #fragment part of a hyperlink URL.
 -->
<xsl:template name="generateCrossRefID">
  <xsl:param name="refNode" select="."/>
  <xsl:call-template name="generateID">
    <xsl:with-param name="keyNode" select="$refNode"/>
    <!--
      - To retain compatibility with IDs generated by previous versions of the template, inline.charseq must be called.
      - The purpose of that template is to generate markup (according to docbook documentation its purpose is to mark/format something as plain text).
      - The only reason to call this template is to get the auto-generated text such as brackets ([]) before flattening it.
      -->
    <xsl:with-param name="templateID">
      <xsl:call-template name="inline.charseq">
        <xsl:with-param name="content" select="$refNode"/>
      </xsl:call-template>
    </xsl:with-param>
  </xsl:call-template>
</xsl:template>

<!--
  - A helper template for disambiguating and collapsing a set of equally valid candidate matches
  - for a given reference down to a single remaining match. This one simply picks the first in the set and
  - retraces/invokes the generateID machinery for/on it.
  - Using a unique value for the mode attribute ensures the template can only be 'called' deliberately,
  - inspite of the match attribute.
  -
  - In debug mode it will output a list of all refs found.
  -
  - This template isn't meant to be used stand-alone, see: flattenToRef
 -->
<xsl:template name="collapseMatchSet" mode="cross-ref-collapse-to-first" match="*">
  <xsl:param name="cross-refs-debug" select="''"/>
  <xsl:if test="$cross-refs-debug!=''">
    <xsl:value-of select="concat('found a reference ... [', position(), ']:&#x09;&#x09;&#x09;', string(.))"/><br/>
  </xsl:if>
  <xsl:if test="position() = 1">
    <xsl:if test="$cross-refs-debug!=''">
      <br/><xsl:value-of select="'==&gt; selected reference, generated ID ==&gt;&#x09;'"/>
    </xsl:if>
    <!-- generate the actual ID -->
    <xsl:call-template name="generateCrossRefID"/>
    <xsl:if test="$cross-refs-debug!=''"><br/><br/></xsl:if>
  </xsl:if>
</xsl:template>

<!--
  - A canary marker/value to indicate bugs/failures to resolve cross reference IDs
  - This value is used only for tagging debug output (if it is generated).
 -->
<xsl:variable name="cross-ref-canary-prefix" select="'please-report-bug-tags-docs-xsl-'"/>

<!--
  - A helper template to generate a #fragment value for a hyperlink URL from a set of valid cross referenced nodes.
  - In debug mode various printf() style debug statements are generated and an empty set is signalled using a marker value.
 -->
<xsl:template name="flattenToRef">
  <xsl:param name="crossRefSet"/>
  <xsl:param name="cross-refs-debug" select="''"/>

  <xsl:if test="$cross-refs-debug!=''">
    <xsl:value-of select="concat('checkRefXML :: found count =&#x09;&#x09;&#x09;',count($crossRefSet))"/><br/>
    <xsl:value-of select="concat('checkRefXML :: local-name =&#x09;&#x09;&#x09;',local-name($crossRefSet))"/><br/>
  </xsl:if>

  <xsl:choose>
    <xsl:when test="count($crossRefSet) != 0">
      <xsl:apply-templates select="$crossRefSet" mode="cross-ref-collapse-to-first">
        <xsl:with-param name="cross-refs-debug" select="$cross-refs-debug"/>
      </xsl:apply-templates>
      <xsl:if test="$cross-refs-debug!=''">
        <br/>
      </xsl:if>
    </xsl:when>
    <!-- A default/catch-all fall back for when the target cannot be related to a valid match. -->
    <xsl:when test="$cross-refs-debug!=''">
      <xsl:value-of select="concat($cross-ref-canary-prefix,'refxml-nomatch')"/>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<xsl:template match="citerefentry[not(refentrytitle/@target)]" mode="cross-refs">
  <xsl:param name="document"/>
  <xsl:param name="cross-refs-debug" select="''"/>
  <!--
    - Avoid selecting based on the title because that would break if ever the documentation is translated into another language.
   -->
  <xsl:variable name="seeAlso" select="//refsect1[last()][count(title|para)=count(*)][title][count(para) &gt; 0]"/>
  <!--
    - Some cross references lack a @target attribute, and for some of those a @target can be automatically inferred.
    - In particular, a fairly common construct is for a list of term nodes to be followed by a citerefentry to another systemd man page without target.
    -->
  <xsl:variable name="terms" select="parent::para/parent::listitem/preceding-sibling::term"/>

  <!--
    - Another common case is a reference to further documentation on a particular option/varname/command/filename type.
    - In that case the likely target is probably right before or after. Try all the relevant sibling nodes.
    -
    - Filter the set of sibling nodes down to a few known types whitelisted in $attemptParaTargets,
    - one of which likely can substitute for an explicit @target.
    - By wrapping local-name() in spaces using concat() substring matches are rejected by contains().
    - Otherwise a hypothetical <i> element would match 'filename' because 'i' is a substring of 'filename'.
   -->
  <xsl:variable name="siblings" select="preceding-sibling::*|following-sibling::*"/>
  <xsl:variable name="attemptParaTargets" select="' option varname command filename  '"/>
  <xsl:variable name="paraSiblings" select="$siblings[contains($attemptParaTargets,concat(' ',local-name(), ' '))]"/>
  <xsl:variable name="refs" select="$terms|$paraSiblings"/>
  <xsl:choose>
    <!-- Special case: C API documentation.   -->
    <xsl:when test="child::manvolnum[string(normalize-space(.)) = '3']">
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="'covered-by-c-api-exception::do-not-infer'"/>
      </xsl:if>
    </xsl:when>
    <!-- Special case: for 'See Also' sections -->
    <xsl:when test="parent::para/parent::refsect1[. = $seeAlso]">
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="'covered-by-see-also-exception::do-not-infer'"/>
      </xsl:if>
    </xsl:when>
    <!-- Sometimes a @target attribute cannot be inferred (no relevant $refs). -->
    <xsl:when test="count($refs) = 0">
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="concat($cross-ref-canary-prefix,'unhandled-citerefentry')"/>
      </xsl:if>
    </xsl:when>
    <xsl:otherwise>
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="concat('checkRefXML :: count REF IDs =&#x09;&#x09;&#x09;', count($refs))"/><br/>
        <xsl:value-of select="concat('checkRefXML :: REF ID text() =&#x09;&#x09;&#x09;', $refs/text())"/><br/>
        <xsl:value-of select="concat('checkRefXML :: REF ID string(.) =&#x09;&#x09;', string($refs))"/><br/>
      </xsl:if>

      <xsl:variable name="found" select="exsl:node-set(refs:findMatchesForID($refs, $document))/*"/>
      <xsl:call-template name="flattenToRef">
        <xsl:with-param name="crossRefSet" select="$found"/>
        <xsl:with-param name="cross-refs-debug" select="$cross-refs-debug"/>
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="citerefentry[refentrytitle/@target]" mode="cross-refs">
  <xsl:param name="document"/>
  <xsl:param name="cross-refs-debug" select="''"/>

  <xsl:variable name="found" select="exsl:node-set(refs:findMatchesForID(refentrytitle/@target, $document))/*"/>
  <xsl:choose>
    <!-- Special case: constants list in systemd.directives. -->
    <xsl:when test="count($found) = 0 and ancestor::variablelist[@id='constants']/ancestor::refentry[@id='systemd.directives']">
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="'covered-by-ignore-list::ignore-failure'"/>
      </xsl:if>
    </xsl:when>
    <!-- Special case: C API documentation. -->
    <xsl:when test="count($found) = 0 and child::manvolnum[string(normalize-space(.)) = '3']">
      <xsl:if test="$cross-refs-debug!=''">
        <xsl:value-of select="'covered-by-c-api-exception::ignore-failure'"/>
      </xsl:if>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="flattenToRef">
        <xsl:with-param name="crossRefSet" select="$found"/>
        <xsl:with-param name="cross-refs-debug" select="$cross-refs-debug"/>
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>
