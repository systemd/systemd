<?xml version='1.0'?> <!--*-nxml-*-->

<!--
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>
<!--
  - The docbook stylesheet injects empty anchor tags into generated HTML, identified by an auto-generated ID.
  - Ask the docbook stylesheet to generate reproducible output when generating (these) ID values.
  - This makes the output of this stylesheet reproducible across identical invocations on the same input,
  - which is an easy and significant win for achieving reproducible builds.
  -
  - It may be even better to strip the empty anchors from the document output in addition to turning on consistent IDs,
  - for this stylesheet contains its own custom ID logic (for generating permalinks) already.
 -->
<xsl:param name="generate.consistent.ids" select="1"/>

<!-- translate man page references to links to html pages -->
<xsl:template match="citerefentry[not(@project)]">
  <a>
    <xsl:attribute name="href">
      <xsl:value-of select="refentrytitle"/><xsl:text>.html</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='man-pages'] | citerefentry[manvolnum='2'] | citerefentry[manvolnum='4']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>http://man7.org/linux/man-pages/man</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
      <xsl:text>.</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>.html</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='die-net']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>http://linux.die.net/man/</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='mankier']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>https://www.mankier.com/</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='archlinux']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>https://www.archlinux.org/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
      <xsl:text>/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
      <xsl:text>.</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>.html</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='freebsd']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>https://www.freebsd.org/cgi/man.cgi?</xsl:text>
      <xsl:value-of select="refentrytitle"/>
      <xsl:text>(</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>)</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<xsl:template match="citerefentry[@project='dbus']">
  <a>
    <xsl:attribute name="href">
      <xsl:text>http://dbus.freedesktop.org/doc/</xsl:text>
      <xsl:value-of select="refentrytitle"/>
      <xsl:text>.</xsl:text>
      <xsl:value-of select="manvolnum"/>
      <xsl:text>.html</xsl:text>
    </xsl:attribute>
    <xsl:call-template name="inline.charseq"/>
  </a>
</xsl:template>

<!--
  - helper template to do conflict resolution between various headings with the same inferred ID attribute/tag from the headerlink template
  - this conflict resolution is necessary to prevent malformed HTML output (multiple id attributes with the same value)
  - and it fixes xsltproc warnings during compilation of HTML man pages
  -
  - A simple top-to-bottom numbering scheme is implemented for nodes with the same ID value to derive unique ID values for HTML output.
  - It uses two parameters:
      templateID  the proposed ID string to use which must be checked for conflicts
      keyNode     the context node which 'produced' the given templateID.
  -
  - Conflicts are detected solely based on keyNode, templateID is not taken into account for that purpose.
 -->
<xsl:template name="generateID">
  <!-- node which generatedID needs to assume as the 'source' of the ID -->
  <xsl:param name="keyNode"/>
  <!-- suggested value for generatedID output, a contextually meaningful ID string -->
  <xsl:param name="templateID"/>
  <xsl:variable name="conflictSource" select="preceding::refsect1/title|preceding::refsect1/info/title|
					      preceding::refsect2/title|preceding::refsect2/info/title|
					      preceding::varlistentry/term[1]"/>
  <xsl:variable name="conflictCount" select="count($conflictSource[. = $keyNode])"/>
  <xsl:choose>
    <!-- special case conflictCount = 0 to preserve compatibility with URLs generated by previous versions of this XSL stylesheet where possible -->
    <xsl:when test="$conflictCount = 0">
      <xsl:value-of select="$templateID"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="concat($templateID, $conflictCount)"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!--
  - a helper template to abstract over the structure of generated subheading + permalink HTML output
  - It helps reduce tedious repetition and groups all actual markup output (as opposed to URL/ID logic) in a single location.
 -->
<xsl:template name="permalink">
  <xsl:param name="nodeType"/> <!-- local name of the element node to generate, e.g. 'h2' for <h2></h2> -->
  <xsl:param name="nodeContent"/> <!-- nodeset to apply further templates to obtain the content of the subheading/term -->
  <xsl:param name="linkTitle"/> <!-- value for title attribute of generated permalink, e.g. 'this is a permalink' -->

  <!-- parameters passed to generateID template, otherwise unused. -->
  <xsl:param name="keyNode"/>
  <xsl:param name="templateID"/>

  <!--
    - If stable URLs with fragment markers (references to the ID) turn out not to be important:
    - generatedID could simply take the value of generate-id(), and various other helper templates may be dropped entirely.
    - Alternatively if xsltproc is patched to generate reproducible generate-id() output the same simplifications can be
    - applied at the cost of breaking compatibility with URLs generated from output of previous versions of this stylesheet.
   -->
  <xsl:variable name="generatedID">
    <xsl:call-template name="generateID">
      <xsl:with-param name="keyNode" select="$keyNode"/>
      <xsl:with-param name="templateID" select="$templateID"/>
    </xsl:call-template>
  </xsl:variable>

  <xsl:element name="{$nodeType}">
    <xsl:attribute name="id">
      <xsl:value-of select="$generatedID"/>
    </xsl:attribute>
    <xsl:apply-templates select="$nodeContent"/>
    <a class="headerlink" title="{$linkTitle}" href="#{$generatedID}">¶</a>
  </xsl:element>
</xsl:template>

<!-- simple wrapper around permalink to avoid repeating common info for each level of subheading covered by the permalink logic (h2, h3) -->
<xsl:template name="headerlink">
  <xsl:param name="nodeType"/>
  <xsl:call-template name="permalink">
    <xsl:with-param name="nodeType" select="$nodeType"/>
    <xsl:with-param name="linkTitle" select="'Permalink to this headline'"/>
    <xsl:with-param name="nodeContent" select="node()"/>
    <xsl:with-param name="keyNode" select="."/>
    <!--
      - To retain compatibility with IDs generated by previous versions of the template, inline.charseq must be called.
      - The purpose of that template is to generate markup (according to docbook documentation its purpose is to mark/format something as plain text).
      - The only reason to call this template is to get the auto-generated text such as brackets ([]) before flattening it.
     -->
    <xsl:with-param name="templateID">
      <xsl:call-template name="inline.charseq"/>
    </xsl:with-param>
  </xsl:call-template>
</xsl:template>

<xsl:template match="refsect1/title|refsect1/info/title">
  <!-- the ID is output in the block.object call for refsect1 -->
  <xsl:call-template name="headerlink">
    <xsl:with-param name="nodeType" select="'h2'"/>
  </xsl:call-template>
</xsl:template>

<xsl:template match="refsect2/title|refsect2/info/title">
  <xsl:call-template name="headerlink">
    <xsl:with-param name="nodeType" select="'h3'"/>
  </xsl:call-template>
</xsl:template>

<xsl:template match="varlistentry">
  <xsl:call-template name="permalink">
    <xsl:with-param name="nodeType" select="'dt'"/>
    <xsl:with-param name="linkTitle" select="'Permalink to this term'"/>
    <xsl:with-param name="nodeContent" select="term"/>
    <xsl:with-param name="keyNode" select="term[1]"/>
    <!--
      - To retain compatibility with IDs generated by previous versions of the template, inline.charseq must be called.
      - The purpose of that template is to generate markup (according to docbook documentation its purpose is to mark/format something as plain text).
      - The only reason to call this template is to get the auto-generated text such as brackets ([]) before flattening it.
     -->
    <xsl:with-param name="templateID">
      <xsl:call-template name="inline.charseq">
	<xsl:with-param name="content" select="term[1]"/>
      </xsl:call-template>
    </xsl:with-param>
  </xsl:call-template>
  <dd>
    <xsl:apply-templates select="listitem"/>
  </dd>
</xsl:template>


<!-- add Index link at top of page -->
<xsl:template name="user.header.content">
  <style>
    a.headerlink {
      color: #c60f0f;
      font-size: 0.8em;
      padding: 0 4px 0 4px;
      text-decoration: none;
      visibility: hidden;
    }

    a.headerlink:hover {
      background-color: #c60f0f;
      color: white;
    }

    h1:hover > a.headerlink, h2:hover > a.headerlink, h3:hover > a.headerlink, dt:hover > a.headerlink {
      visibility: visible;
    }
  </style>

  <a>
    <xsl:attribute name="href">
      <xsl:text>index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>Index </xsl:text>
  </a>·
  <a>
    <xsl:attribute name="href">
      <xsl:text>systemd.directives.html</xsl:text>
    </xsl:attribute>
    <xsl:text>Directives </xsl:text>
  </a>

  <span style="float:right">
    <xsl:text>systemd </xsl:text>
    <xsl:value-of select="$systemd.version"/>
  </span>
  <hr/>
</xsl:template>

<xsl:template match="literal">
  <xsl:text>"</xsl:text>
  <xsl:call-template name="inline.monoseq"/>
  <xsl:text>"</xsl:text>
</xsl:template>

<!-- Switch things to UTF-8, ISO-8859-1 is soo yesteryear -->
<xsl:output method="html" encoding="UTF-8" indent="no"/>

</xsl:stylesheet>
