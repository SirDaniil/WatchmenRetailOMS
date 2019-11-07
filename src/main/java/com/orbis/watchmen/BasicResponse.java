package com.orbis.watchmen;

/**
 * User: Daniil Sosonkin
 * Date: 8/22/2018 9:01 AM
 */
public final class BasicResponse
    {
        private boolean success;
        private Object content;

        public boolean isSuccess()
            {
                return success;
            }

        public void setSuccess(boolean success)
            {
                this.success = success;
            }

        public Object getContent()
            {
                return content;
            }

        public void setContent(Object content)
            {
                this.content = content;
            }
    }