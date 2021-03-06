/*
 *   SONEWS News Server
 *   see AUTHORS for the list of contributors
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package dibd.daemon.command;

import java.io.IOException;
import java.util.List;

import dibd.daemon.NNTPConnection;
import dibd.daemon.NNTPInterface;
import dibd.storage.StorageBackendException;
import dibd.storage.StorageManager;
import dibd.storage.article.Article;
import dibd.util.Log;

/**
 * Class handling the OVER/XOVER command.
 * 
 * Description of the XOVER command:
 * 
 * <pre>
 * XOVER [range]
 *
 * The XOVER command returns information from the overview
 * database for the article(s) specified.
 *
 * The optional range argument may be any of the following:
 *              an article number
 *              an article number followed by a dash to indicate
 *                 all following
 *              an article number followed by a dash followed by
 *                 another article number
 *
 * If no argument is specified, then information from the
 * current article is displayed. Successful responses start
 * with a 224 response followed by the overview information
 * for all matched messages. Once the output is complete, a
 * period is sent on a line by itself. If no argument is
 * specified, the information for the current article is
 * returned.  A news group must have been selected earlier,
 * else a 412 error response is returned. If no articles are
 * in the range specified, a 420 error response is returned
 * by the server. A 502 response will be returned if the
 * client only has permission to transfer articles.
 *
 * Each line of output will be formatted with the article number,
 * followed by each of the headers in the overview database or the
 * article itself (when the data is not available in the overview
 * database) for that article separated by a tab character.  The
 * sequence of fields must be in this order: subject, author,
 * date, message-id, references, byte count, and line count. Other
 * optional fields may follow line count. Other optional fields may
 * follow line count. These fields are specified by examining the
 * response to the LIST OVERVIEW.FMT command. Where no data exists,
 * a null field must be provided (i.e. the output will have two tab
 * characters adjacent to each other). Servers should not output
 * fields for articles that have been removed since the XOVER database
 * was created.
 *
 * The LIST OVERVIEW.FMT command should be implemented if XOVER
 * is implemented. A client can use LIST OVERVIEW.FMT to determine
 * what optional fields  and in which order all fields will be
 * supplied by the XOVER command. 
 *
 * Note that any tab and end-of-line characters in any header
 * data that is returned will be converted to a space character.
 *
 * Responses:
 *
 *   224 Overview information follows
 *   412 No news group current selected
 *   420 No article(s) selected
 *   502 no permission
 *
 * OVER defines additional responses:
 *
 *  First form (message-id specified)
 *    224    Overview information follows (multi-line)
 *    430    No article with that message-id
 *
 *  Second form (range specified)
 *    224    Overview information follows (multi-line)
 *    412    No newsgroup selected
 *    423    No articles in that range
 *
 *  Third form (current article number used)
 *    224    Overview information follows (multi-line)
 *    412    No newsgroup selected
 *    420    Current article number is invalid
 *
 * </pre>
 * 
 * @author Christian Lins
 * @since sonews/0.5.0
 */
public class OverCommand implements Command {

    //public static final int MAX_LINES_PER_DBREQUEST = 200;

    @Override
    public String[] getSupportedCommandStrings() {
        return new String[] { "OVER", "XOVER" };
    }

    @Override
    public boolean hasFinished() {
        return true;
    }

    @Override
    public String impliedCapability() {
        return null;
    }

    @Override
    public boolean isStateful() {
        return false;
    }

    @Override
    public void processLine(NNTPInterface conn, final String line, byte[] raw)
            throws IOException, StorageBackendException {
        if (conn.getCurrentGroup() == null) {
            conn.println("412 no newsgroup selected");
        } else {
            String[] command = line.split("\\p{Space}+");

            // If no parameter was specified, show information about
            // the currently selected article(s)
            if (command.length == 1) {
                final Article art = conn.getCurrentArticle();
                if (art == null) {
                    conn.println("420 no article(s) selected");
                    return;
                }

                conn.println(buildOverview(art, -1));
            } // otherwise print information about the specified range
            else {
                long artStart;
                long artEnd = conn.getCurrentGroup().getLastArticleNumber();
                String[] nums = command[1].split("-");
                if (nums.length >= 1) {
                    try {
                        artStart = Integer.parseInt(nums[0]);
                    } catch (NumberFormatException e) {
                        Log.get().info(e.getMessage());
                        artStart = Integer.parseInt(command[1]);
                    }
                } else {
                    artStart = conn.getCurrentGroup().getFirstArticleNumber();
                }

                if (nums.length >= 2) {
                    try {
                        artEnd = Integer.parseInt(nums[1]);
                    } catch (NumberFormatException e) {
                        e.printStackTrace();
                    }
                }

                if (artStart > artEnd) {
                    if (command[0].equalsIgnoreCase("OVER")) {
                        conn.println("423 no articles in that range");
                    } else {
                        conn.println("224 (empty) overview information follows:");
                        conn.println(".");
                    }
                } else {
                 //   for (long n = artStart; n <= artEnd; n += MAX_LINES_PER_DBREQUEST) {
                   //     long nEnd = Math.min(n + MAX_LINES_PER_DBREQUEST - 1,
                     //           artEnd);
                        //List<Pair<Long, ArticleHead>> articleHeads = conn.getCurrentChannel().getArticleHeads(n, nEnd);
                        //List<Integer> mid = StorageManager.current().getArticleNumbers(conn.getCurrentGroup().getInternalID(), (int)n);
                        List<Integer> mid = StorageManager.current().getArticleNumbers(conn.getCurrentGroup().getInternalID(), 0);
                        //if (articleHeads.isEmpty() && n == artStart
                          //      && command[0].equalsIgnoreCase("OVER")) {
                        
                        //if (( mid.isEmpty() || n == artStart)
                        if (mid.isEmpty() 
                                     && command[0].equalsIgnoreCase("OVER")) {
                            // This reply is only valid for OVER, not for XOVER
                            // command
                            conn.println("423 no articles in that range");
                            return;
                        } else{ //if (n == artStart) {
                            // XOVER replies this although there is no data
                            // available
                            conn.println("224 overview information follows");
                        }
                        /*
                        for (Pair<Long, ArticleHead> article : articleHeads) {
                            String overview = buildOverview(article.getB(),
                                    article.getA());
                            conn.println(overview);
                        }*/
                        //int count = 0; 
                        for(int id : mid){
                      //  	if(count++ < MAX_LINES_PER_DBREQUEST){
                        		//System.out.println("AAAAAAAAAAAAAAAAAAAAAid:"+id);
                        		Article a = StorageManager.current().getArticle(null, id);
                        		String overview = buildOverview(a,id);
                        		System.out.println("Aid:"+ a.getId()+ " "+a.getThread_id());
                        		conn.println(overview);
                        		
                        //	}
                        }	
                    //} // for
                    conn.println(".");
                }
            }
        }
    }

    private String buildOverview(Article art, long nr) throws StorageBackendException {
        StringBuilder overview = new StringBuilder();
        //1) number
        overview.append(nr)
        .append('\t');
        //2) Subject
        String subject = art.getSubject();
        overview.append(escapeString(subject))
        .append('\t');
        //3) from
        String name = art.getA_name();
        overview.append(escapeString(name))
        .append('\t');
        //4)date
        overview.append(escapeString(art.getDate()))
        .append('\t');
        //5)message-Id
        overview.append(escapeString(art.getMessageId()))
        .append('\t');
        //6) thread-Id
        if(art.getThread_id()!=art.getId())
        	overview.append(StorageManager.current().getArticle(null, art.getThread_id()).getMessageId());
        //overview.append('\t');

        //String bytes = art.getHeader(Headers.BYTES)[0];
        /*String bytes = "";
        if ("".equals(bytes)) {
            bytes = "0";
        }
        overview.append(escapeString(bytes));
        overview.append('\t');

        //String lines = art.getHeader(Headers.LINES)[0];
        String lines = "";
        if ("".equals(lines)) {
            lines = "0";
        }
        overview.append(escapeString(lines));
        overview.append('\t');
        //overview.append(escapeString(art.getHeader(Headers.XREF)[0]));
*/
        // Remove trailing tabs if some data is empty
        return overview.toString().trim();
    }

    private String escapeString(String str) {
        String nstr = str.replace("\r", "");
        nstr = nstr.replace('\n', ' ');
        nstr = nstr.replace('\t', ' ');
        return nstr.trim();
    }
}
