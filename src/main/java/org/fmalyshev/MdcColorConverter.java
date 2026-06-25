package org.fmalyshev;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

public class MdcColorConverter extends ClassicConverter {
    @Override
    public String convert(ILoggingEvent event) {
        // Читаем код цвета из MDC, если его нет — ставим дефолтный (0 - сброс)
        String colorCode = event.getMDCPropertyMap().get("moduleColor");
        if (colorCode == null) {
            colorCode = "0"; // Стандартный цвет
        }
        // Возвращаем управляющий ANSI-код: \u001B[код_цветаm
        return "\u001B[" + colorCode + "m";
    }
}