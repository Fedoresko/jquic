package org.jquic;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

public class MdcColorConverter extends ClassicConverter {
    @Override
    public String convert(ILoggingEvent event) {
        String colorCode = event.getMDCPropertyMap().get("moduleColor");
        if (colorCode == null) {
            colorCode = "0"; // Стандартный цвет
        }
        return "\u001B[" + colorCode + "m";
    }
}