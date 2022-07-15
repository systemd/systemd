<?xml version='1.0'?> <!--*-nxml-*-->

<!--
  SPDX-License-Identifier: LGPL-2.1-or-later
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl"
                version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/>

<xsl:template name="top.comment" />

<xsl:template name="TH.title.line">
    <xsl:param name="title"/>
    <xsl:param name="section"/>
    <xsl:param name="extra1"/>
    <xsl:param name="extra2"/>
    <xsl:param name="extra3"/>

    <xsl:call-template name="mark.subheading"/>
    <xsl:text>.TH "</xsl:text>
    <xsl:call-template name="string.upper">
      <xsl:with-param name="string">
        <xsl:value-of select="normalize-space($title)"/>
      </xsl:with-param>
    </xsl:call-template>
    <xsl:text>" "</xsl:text>
    <xsl:value-of select="normalize-space($section)"/>
    <xsl:text>" "" "systemd </xsl:text>
    <xsl:value-of select="$systemd.version"/>
    <xsl:text>" "</xsl:text>
    <xsl:value-of select="normalize-space($extra3)"/>
    <xsl:text>"&#10;</xsl:text>
    <xsl:call-template name="mark.subheading"/>
</xsl:template>

<xsl:template match="literal">
  <xsl:if test="$man.hyphenate.computer.inlines = 0">
    <xsl:call-template name="suppress.hyphenation"/>
  </xsl:if>
  <xsl:text>"</xsl:text>
  <xsl:call-template name="inline.monoseq"/>
  <xsl:text>"</xsl:text>
</xsl:template>

</xsl:stylesheet>
