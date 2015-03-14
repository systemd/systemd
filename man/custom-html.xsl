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

<xsl:template match="refsect1/title|refsect1/info/title">
  <!-- the ID is output in the block.object call for refsect1 -->
  <h2>
    <xsl:attribute name="id">
      <xsl:call-template name="inline.charseq"/>
    </xsl:attribute>
    <xsl:apply-templates/>
    <a>
      <xsl:attribute name="class">
        <xsl:text>headerlink</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="title">
        <xsl:text>Permalink to this headline</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="href">
        <xsl:text>#</xsl:text>
        <xsl:call-template name="inline.charseq"/>
      </xsl:attribute>
      <xsl:text>¶</xsl:text>
    </a>
  </h2>
</xsl:template>

<xsl:template match="refsect2/title|refsect2/info/title">
  <h3>
    <xsl:attribute name="id">
      <xsl:call-template name="inline.charseq"/>
    </xsl:attribute>
    <xsl:apply-templates/>
    <a>
      <xsl:attribute name="class">
        <xsl:text>headerlink</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="title">
        <xsl:text>Permalink to this headline</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="href">
        <xsl:text>#</xsl:text>
        <xsl:call-template name="inline.charseq"/>
      </xsl:attribute>
      <xsl:text>¶</xsl:text>
    </a>
  </h3>
</xsl:template>

<xsl:template match="varlistentry">
  <dt>
    <xsl:attribute name="id">
      <xsl:call-template name="inline.charseq">
        <xsl:with-param name="content">
          <xsl:copy-of select="term[position()=1]" />
        </xsl:with-param>
      </xsl:call-template>
    </xsl:attribute>
    <xsl:apply-templates select="term"/>
    <a>
      <xsl:attribute name="class">
        <xsl:text>headerlink</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="title">
        <xsl:text>Permalink to this term</xsl:text>
      </xsl:attribute>
      <xsl:attribute name="href">
        <!--        <xsl:call-template name="href.target.uri" /> -->
        <xsl:text>#</xsl:text>
        <xsl:call-template name="inline.charseq">
          <xsl:with-param name="content">
            <xsl:copy-of select="term[position()=1]" />
          </xsl:with-param>
        </xsl:call-template>
      </xsl:attribute>
      <xsl:text>¶</xsl:text>
    </a>
  </dt>
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
  </a>·
  <a>
    <xsl:attribute name="href">
      <xsl:text>../python-systemd/index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>Python </xsl:text>
  </a>·
  <a>
    <xsl:attribute name="href">
      <xsl:text>../libudev/index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>libudev </xsl:text>
  </a>·
  <a>
    <xsl:attribute name="href">
      <xsl:text>../libudev/index.html</xsl:text>
    </xsl:attribute>
    <xsl:text>gudev </xsl:text>
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
