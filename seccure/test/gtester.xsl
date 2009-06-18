<?xml version="1.0"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:for-each select="gtester/testbinary">
            <testsuite>
                <xsl:attribute name="name">
                    <xsl:value-of select="@path"/>
                </xsl:attribute>
                <xsl:attribute name="tests">
                    <xsl:value-of select="count(testcase)"/>
                </xsl:attribute>
                <xsl:attribute name="time">
                    <xsl:value-of select="sum(testcase/duration)"/>
                </xsl:attribute>
                <xsl:attribute name="failures">
                    <xsl:value-of select="count(testcase/status[@result='failed'])"/>
                </xsl:attribute>
                <xsl:for-each select="testcase">
                    <testcase>
                        <xsl:attribute name="classname">
                            <xsl:value-of select="@path"/>
                        </xsl:attribute>
                        <xsl:attribute name="name">g_test</xsl:attribute>
                        <xsl:attribute name="time">
                            <xsl:value-of select="duration"/>
                        </xsl:attribute>
                        <xsl:if test="status[@result = 'failed']">
                            <failure>
                                <xsl:value-of select="error"/>
                            </failure>
                        </xsl:if>
                    </testcase>
                </xsl:for-each>
            </testsuite>
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>


